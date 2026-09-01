//! End-to-end tests over a real socket.
//!
//! The unit tests cover the protocol; these cover the wiring. The bugs that
//! live here are the ones a real client provokes and a state machine test
//! cannot: a body arriving in the same packet as `DATA`, a terminator split
//! across reads, a second message reusing the connection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use pigeon_smtp::{DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};

// ---------------------------------------------------------------- test sink

#[derive(Clone)]
struct TestSink {
    allowed: Arc<Vec<String>>,
    received: Arc<Mutex<Vec<Message>>>,
}

impl TestSink {
    fn new(allowed: &[&str]) -> Self {
        Self {
            allowed: Arc::new(allowed.iter().map(|s| s.to_string()).collect()),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn messages(&self) -> Vec<Message> {
        self.received.lock().unwrap().clone()
    }
}

impl MessageSink for TestSink {
    type Transaction = ();

    fn begin(&self) {}

    fn accepts_recipient(&self, _txn: &mut (), address: &str, _accepted: &[String]) -> Recipient {
        if self.allowed.iter().any(|a| a == address) {
            Recipient::Accept
        } else {
            Recipient::Reject
        }
    }

    async fn deliver(&self, _txn: (), message: Message) -> Result<String, DataError> {
        self.received.lock().unwrap().push(message);
        Ok("TESTID".to_string())
    }
}

// -------------------------------------------------------------- test client

struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let (r, w) = TcpStream::connect(addr).await.unwrap().into_split();
        let mut c = Self {
            reader: BufReader::new(r),
            writer: w,
        };
        assert_eq!(c.read_reply().await.0, 220, "expected banner");
        c
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    /// Read one complete reply, following continuation lines.
    async fn read_reply(&mut self) -> (u16, String) {
        let mut whole = String::new();
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await.unwrap();
            assert!(n > 0, "connection closed, got so far: {whole:?}");
            whole.push_str(&line);

            // The last line of a reply separates code and text with a space;
            // continuations use a hyphen.
            let b = line.as_bytes();
            if b.len() >= 4 && b[3] == b' ' {
                let code: u16 = line[..3].parse().unwrap();
                return (code, whole);
            }
        }
    }

    async fn cmd(&mut self, line: &str) -> u16 {
        self.send(line.as_bytes()).await;
        self.read_reply().await.0
    }

    async fn greet(&mut self) {
        assert_eq!(self.cmd("EHLO client.test\r\n").await, 250);
    }
}

async fn start(sink: TestSink) -> SocketAddr {
    start_with(
        sink,
        ServerConfig {
            hostname: "mx.test".into(),
            ..Default::default()
        },
    )
    .await
}

async fn start_with(sink: TestSink, config: ServerConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = pigeon_smtp::serve(listener, config, sink).await;
    });
    addr
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn delivers_a_message() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    assert_eq!(c.cmd("MAIL FROM:<sender@example.org>\r\n").await, 250);
    assert_eq!(c.cmd("RCPT TO:<hello@example.net>\r\n").await, 250);
    assert_eq!(c.cmd("DATA\r\n").await, 354);
    assert_eq!(c.cmd("Subject: hi\r\n\r\nBody here.\r\n.\r\n").await, 250);
    assert_eq!(c.cmd("QUIT\r\n").await, 221);

    let msgs = sink.messages();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].envelope.sender, "sender@example.org");
    assert_eq!(msgs[0].envelope.recipients, vec!["hello@example.net"]);
    assert_eq!(msgs[0].body, b"Subject: hi\r\n\r\nBody here.\r\n");
}

#[tokio::test]
async fn adds_a_received_header() {
    // RFC 5321 §4.4 requires one on everything relayed, and it is the only
    // loop guard that works across systems Pigeon cannot see.
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<a@example.org>\r\n").await;
    c.cmd("RCPT TO:<hello@example.net>\r\n").await;
    c.cmd("DATA\r\n").await;
    c.cmd("Subject: traced\r\n\r\nhi\r\n.\r\n").await;

    let msg = &sink.messages()[0];
    let h = &msg.received;

    assert!(
        h.starts_with("Received: from client.test "),
        "bad opening: {h:?}"
    );
    assert!(
        h.contains("by mx.test with ESMTP"),
        "missing receiver: {h:?}"
    );
    assert!(h.contains("127.0.0.1"), "missing peer address: {h:?}");
    assert!(
        h.contains("for <hello@example.net>"),
        "missing for clause: {h:?}"
    );
    assert!(h.ends_with("\r\n"), "header must be CRLF-terminated: {h:?}");

    // The body itself is untouched — a signature over it must still verify.
    assert_eq!(msg.body, b"Subject: traced\r\n\r\nhi\r\n");
    assert!(msg.to_bytes().starts_with(b"Received:"));
}

#[tokio::test]
async fn received_header_omits_recipients_when_there_are_several() {
    // Naming every recipient would disclose each one's address to all the
    // others.
    let sink = TestSink::new(&["a@example.net", "b@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<s@example.org>\r\n").await;
    c.cmd("RCPT TO:<a@example.net>\r\n").await;
    c.cmd("RCPT TO:<b@example.net>\r\n").await;
    c.cmd("DATA\r\n").await;
    c.cmd("hi\r\n.\r\n").await;

    let h = &sink.messages()[0].received;
    assert!(
        !h.contains("for <"),
        "leaked recipients to each other: {h:?}"
    );
    assert!(!h.contains("b@example.net"), "leaked a recipient: {h:?}");
}

#[tokio::test]
async fn unknown_recipient_is_refused_before_data() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    assert_eq!(c.cmd("MAIL FROM:<a@example.org>\r\n").await, 250);
    // Refused at RCPT, so the sender never transmits a body and Pigeon never
    // becomes responsible for bouncing it.
    assert_eq!(c.cmd("RCPT TO:<nobody@example.net>\r\n").await, 550);
    assert_eq!(c.cmd("DATA\r\n").await, 503);
    assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn body_pipelined_with_the_data_command() {
    // The body arrives in the same packet as DATA, so those bytes sit in the
    // line reader rather than on the socket. Losing them here would hang the
    // connection until it timed out.
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<a@example.org>\r\n").await;
    c.cmd("RCPT TO:<hello@example.net>\r\n").await;

    c.send(b"DATA\r\nPipelined body\r\n.\r\n").await;
    assert_eq!(c.read_reply().await.0, 354);
    assert_eq!(c.read_reply().await.0, 250);

    let msgs = sink.messages();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].body, b"Pipelined body\r\n");
}

#[tokio::test]
async fn whole_transaction_pipelined_in_one_write() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.send(
        b"EHLO client.test\r\n\
          MAIL FROM:<a@example.org>\r\n\
          RCPT TO:<hello@example.net>\r\n\
          DATA\r\n\
          All at once\r\n.\r\n\
          QUIT\r\n",
    )
    .await;

    for expected in [250u16, 250, 250, 354, 250, 221] {
        assert_eq!(c.read_reply().await.0, expected);
    }
    assert_eq!(sink.messages()[0].body, b"All at once\r\n");
}

#[tokio::test]
async fn terminator_split_across_packets() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<a@example.org>\r\n").await;
    c.cmd("RCPT TO:<hello@example.net>\r\n").await;
    assert_eq!(c.cmd("DATA\r\n").await, 354);

    // Split the end-of-data marker down the middle.
    c.send(b"Line one\r\nLine two\r\n.").await;
    c.send(b"\r\n").await;
    assert_eq!(c.read_reply().await.0, 250);

    assert_eq!(sink.messages()[0].body, b"Line one\r\nLine two\r\n");
}

#[tokio::test]
async fn dot_stuffing_is_removed_over_the_wire() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<a@example.org>\r\n").await;
    c.cmd("RCPT TO:<hello@example.net>\r\n").await;
    c.cmd("DATA\r\n").await;
    assert_eq!(c.cmd("..hidden\r\nnormal\r\n.\r\n").await, 250);

    assert_eq!(sink.messages()[0].body, b".hidden\r\nnormal\r\n");
}

#[tokio::test]
async fn connection_carries_several_messages() {
    let sink = TestSink::new(&["a@example.net", "b@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    for rcpt in ["a@example.net", "b@example.net"] {
        assert_eq!(c.cmd("MAIL FROM:<s@example.org>\r\n").await, 250);
        assert_eq!(c.cmd(&format!("RCPT TO:<{rcpt}>\r\n")).await, 250);
        assert_eq!(c.cmd("DATA\r\n").await, 354);
        assert_eq!(c.cmd("hi\r\n.\r\n").await, 250);
    }

    let msgs = sink.messages();
    assert_eq!(msgs.len(), 2);
    // Each transaction stands alone; recipients must not accumulate.
    assert_eq!(msgs[0].envelope.recipients, vec!["a@example.net"]);
    assert_eq!(msgs[1].envelope.recipients, vec!["b@example.net"]);
}

#[tokio::test]
async fn oversized_message_is_refused_without_dropping_the_connection() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start_with(
        sink.clone(),
        ServerConfig {
            hostname: "mx.test".into(),
            max_message_size: 32,
            ..Default::default()
        },
    )
    .await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    c.cmd("MAIL FROM:<a@example.org>\r\n").await;
    c.cmd("RCPT TO:<hello@example.net>\r\n").await;
    c.cmd("DATA\r\n").await;

    let big = format!("{}\r\n.\r\n", "x".repeat(500));
    assert_eq!(c.cmd(&big).await, 552);

    // Still usable: the reader drained to the terminator instead of bailing.
    assert_eq!(c.cmd("NOOP\r\n").await, 250);
    assert_eq!(c.cmd("QUIT\r\n").await, 221);
    assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn starttls_is_not_offered_without_tls() {
    let sink = TestSink::new(&[]);
    let addr = start(sink).await;
    let mut c = Client::connect(addr).await;

    c.send(b"EHLO client.test\r\n").await;
    let (code, text) = c.read_reply().await;
    assert_eq!(code, 250);
    assert!(
        !text.contains("STARTTLS"),
        "advertised TLS it cannot do: {text}"
    );
    assert_eq!(c.cmd("STARTTLS\r\n").await, 454);
}

#[tokio::test]
async fn null_sender_bounce_is_accepted() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;
    let mut c = Client::connect(addr).await;

    c.greet().await;
    assert_eq!(c.cmd("MAIL FROM:<>\r\n").await, 250);
    assert_eq!(c.cmd("RCPT TO:<hello@example.net>\r\n").await, 250);
    c.cmd("DATA\r\n").await;
    assert_eq!(c.cmd("bounce\r\n.\r\n").await, 250);

    assert!(sink.messages()[0].envelope.is_bounce());
}

#[tokio::test]
async fn client_delivers_to_server() {
    // The two halves against each other. Anything the client writes, the
    // server must recover byte for byte — which is the property that decides
    // whether forwarded mail keeps its DKIM signature.
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;

    let envelope = Envelope {
        sender: "sender@example.org".into(),
        recipients: vec!["hello@example.net".into()],
    };
    // A body containing everything that has to survive the round trip: a
    // line-initial dot, and a line that is nothing but a dot.
    let body = b"Subject: round trip\r\n\r\n.leading dot\r\n.\r\nplain\r\n";

    let stream = TcpStream::connect(addr).await.unwrap();
    let accepted = pigeon_smtp::deliver(stream, "client.test", &envelope, &[body.as_slice()], None)
        .await
        .expect("delivery should succeed");

    assert_eq!(accepted.code, 250);

    let msgs = sink.messages();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].envelope.sender, "sender@example.org");
    assert_eq!(msgs[0].body, body, "body was altered in transit");
}

#[tokio::test]
async fn client_reports_rejected_recipient_as_permanent() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;

    let envelope = Envelope {
        sender: "sender@example.org".into(),
        recipients: vec!["nobody@example.net".into()],
    };

    let stream = TcpStream::connect(addr).await.unwrap();
    let err = pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"x\r\n".as_slice()],
        None,
    )
    .await
    .expect_err("unknown recipient must fail");

    // 550 means retrying is pointless; the queue should bounce rather than
    // spend five days on a mailbox that does not exist.
    assert!(err.is_permanent(), "expected permanent, got {err}");
    assert!(sink.messages().is_empty());
}

#[tokio::test]
async fn client_delivers_a_bounce_with_a_null_sender() {
    let sink = TestSink::new(&["hello@example.net"]);
    let addr = start(sink.clone()).await;

    let envelope = Envelope {
        sender: String::new(),
        recipients: vec!["hello@example.net".into()],
    };

    let stream = TcpStream::connect(addr).await.unwrap();
    pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"delivery failed\r\n".as_slice()],
        None,
    )
    .await
    .unwrap();

    assert!(sink.messages()[0].envelope.is_bounce());
}

#[tokio::test]
async fn garbage_eventually_closes_the_connection() {
    let sink = TestSink::new(&[]);
    let addr = start(sink).await;
    let mut c = Client::connect(addr).await;
    c.greet().await;

    let mut last = 0;
    for _ in 0..12 {
        // Tolerant of failure: once the server hangs up, writing errors rather
        // than the test panicking on an expected condition.
        if c.writer.write_all(b"NONSENSE\r\n").await.is_err() {
            break;
        }
        let mut line = String::new();
        match c.reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => last = line.get(..3).and_then(|s| s.parse().ok()).unwrap_or(0),
        }
    }
    assert_eq!(last, 421, "should give up on a client sending only garbage");
}
