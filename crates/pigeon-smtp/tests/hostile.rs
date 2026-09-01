//! The server's defences, and the property that must never fail.
//!
//! Two things are checked here that nothing else covers.
//!
//! The limits — connection cap, command and data timeouts, survival of an
//! abrupt disconnect — are defensive code that was never exercised. Untested
//! defences are worse than absent ones, because a configuration field that
//! reads as protection invites you to rely on it.
//!
//! And relay refusal, which `SECURITY.md` calls release-blocking. The half of
//! that matrix which needs authenticated submission cannot be tested until
//! port 587 exists; the half that does not need it is live code today and is
//! tested here.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pigeon_smtp::{DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};
use pigeon_testkit::RawClient;

/// Accepts only addresses on domains this server owns.
#[derive(Clone)]
struct LocalOnly {
    domains: Arc<Vec<String>>,
    received: Arc<Mutex<Vec<Envelope>>>,
}

impl LocalOnly {
    fn new(domains: &[&str]) -> Self {
        Self {
            domains: Arc::new(domains.iter().map(|d| d.to_string()).collect()),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

impl MessageSink for LocalOnly {
    type Transaction = ();

    fn begin(&self) {}

    fn accepts_recipient(&self, _txn: &mut (), address: &str, _accepted: &[String]) -> Recipient {
        let carried = match address.rsplit_once('@') {
            Some((_, domain)) => self.domains.iter().any(|d| d.eq_ignore_ascii_case(domain)),
            None => false,
        };
        if carried {
            Recipient::Accept
        } else {
            Recipient::Reject
        }
    }

    async fn deliver(&self, _txn: (), message: Message) -> Result<String, DataError> {
        self.received.lock().unwrap().push(message.envelope);
        Ok("OK".into())
    }
}

async fn start(sink: LocalOnly, config: ServerConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = pigeon_smtp::serve(listener, config, sink).await;
    });
    addr
}

fn config() -> ServerConfig {
    ServerConfig {
        hostname: "mx.test".into(),
        ..Default::default()
    }
}

// ------------------------------------------------------------ relay refusal

#[tokio::test]
async fn refuses_recipients_on_domains_it_does_not_own() {
    // The release-blocking property: an unauthenticated sender on port 25 must
    // not be able to hand Pigeon mail addressed somewhere else. Getting this
    // wrong makes the host an open relay, which ends with the IP on every
    // blocklist within hours.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    let mut c = RawClient::connect(addr).await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 220);
    c.send(b"EHLO attacker.test\r\n").await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 250);
    c.send(b"MAIL FROM:<attacker@attacker.test>\r\n")
        .await
        .unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 250);

    for victim in [
        "victim@somewhere-else.com",
        "victim@gmail.com",
        "VICTIM@SOMEWHERE-ELSE.COM",
        "victim@example.net.attacker.test",
    ] {
        c.send(format!("RCPT TO:<{victim}>\r\n").as_bytes())
            .await
            .unwrap();
        let (code, _) = c.read_reply().await.unwrap();
        assert_eq!(code, 550, "would have relayed for {victim}");
    }

    // DATA must stay refused, since no recipient was ever accepted.
    c.send(b"DATA\r\n").await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 503);
    assert_eq!(sink.count(), 0);
}

#[tokio::test]
async fn accepts_recipients_on_domains_it_does_own() {
    // The other half: refusing everything would also pass the test above.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"EHLO sender.test\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"MAIL FROM:<someone@sender.test>\r\n")
        .await
        .unwrap();
    c.read_reply().await.unwrap();
    c.send(b"RCPT TO:<hello@EXAMPLE.NET>\r\n").await.unwrap();
    assert_eq!(
        c.read_reply().await.unwrap().0,
        250,
        "domain match must ignore case"
    );
    c.send(b"DATA\r\n").await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 354);
    c.send(b"hi\r\n.\r\n").await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 250);

    assert_eq!(sink.count(), 1);
}

// -------------------------------------------------------------------- limits

#[tokio::test]
async fn connection_cap_holds_back_the_surplus() {
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(
        sink,
        ServerConfig {
            max_connections: 2,
            ..config()
        },
    )
    .await;

    // Two get served.
    let mut a = RawClient::connect(addr).await.unwrap();
    let mut b = RawClient::connect(addr).await.unwrap();
    assert_eq!(a.read_reply().await.unwrap().0, 220);
    assert_eq!(b.read_reply().await.unwrap().0, 220);

    // The third completes its TCP handshake but gets no banner, because the
    // permit is taken before the connection is served. Queued, not refused —
    // a burst should wait rather than bounce.
    let mut c = RawClient::connect(addr).await.unwrap();
    assert!(
        c.read_reply_within(Duration::from_millis(250))
            .await
            .is_none(),
        "third connection was served despite the cap"
    );

    // Freeing a slot lets it through.
    a.disconnect();
    assert_eq!(
        c.read_reply_within(Duration::from_secs(2))
            .await
            .map(|r| r.0),
        Some(220),
        "slot did not free after a connection closed"
    );
}

#[tokio::test]
async fn idle_client_is_disconnected_rather_than_held_forever() {
    // Slowloris: open connections and say nothing. Without a command timeout
    // each one occupies a slot indefinitely, and the cap above becomes the
    // means of denial rather than the defence against it.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(
        sink,
        ServerConfig {
            command_timeout: Duration::from_millis(150),
            ..config()
        },
    )
    .await;

    let mut c = RawClient::connect(addr).await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 220);

    // Say nothing at all.
    let (code, _) = c
        .read_reply_within(Duration::from_secs(2))
        .await
        .expect("expected a timeout reply");
    assert_eq!(
        code, 421,
        "should announce the timeout rather than vanishing"
    );
    assert!(c.is_closed(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn stalling_mid_body_also_times_out() {
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(
        sink.clone(),
        ServerConfig {
            data_timeout: Duration::from_millis(150),
            ..config()
        },
    )
    .await;

    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"EHLO slow.test\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"MAIL FROM:<a@slow.test>\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"RCPT TO:<hello@example.net>\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"DATA\r\n").await.unwrap();
    assert_eq!(c.read_reply().await.unwrap().0, 354);

    // Start a body and never finish it.
    c.send(b"Subject: never ends\r\n").await.unwrap();

    let (code, _) = c
        .read_reply_within(Duration::from_secs(2))
        .await
        .expect("expected a timeout");
    assert_eq!(code, 421);
    // An unfinished message must not be delivered.
    assert_eq!(sink.count(), 0);
}

#[tokio::test]
async fn disconnecting_mid_body_leaves_the_server_healthy() {
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    for _ in 0..5 {
        let mut c = RawClient::connect(addr).await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"EHLO rude.test\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"MAIL FROM:<a@rude.test>\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"RCPT TO:<hello@example.net>\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"DATA\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"Subject: half a mes").await.unwrap();
        c.disconnect(); // vanish mid-body
    }

    // Nothing partial was delivered, and the server still works.
    assert_eq!(sink.count(), 0, "a partial message must never be delivered");

    let mut good = RawClient::connect(addr).await.unwrap();
    assert_eq!(good.read_reply().await.unwrap().0, 220);
    good.send(b"EHLO fine.test\r\n").await.unwrap();
    assert_eq!(good.read_reply().await.unwrap().0, 250);
}

#[tokio::test]
async fn partial_command_across_writes_is_reassembled() {
    // Byte-at-a-time delivery is what a slow link, or a probe, looks like.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink, config()).await;

    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();

    for byte in b"EHLO drip.test\r\n" {
        c.send(&[*byte]).await.unwrap();
    }
    assert_eq!(c.read_reply().await.unwrap().0, 250);
}

// ------------------------------------------------------------ malformed input

/// Send one message and return the reply to the terminating dot.
async fn submit_body(addr: SocketAddr, body: &[u8]) -> (u16, String) {
    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"EHLO sender.test\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"MAIL FROM:<a@sender.test>\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"RCPT TO:<hello@example.net>\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"DATA\r\n").await.unwrap();
    c.read_reply().await.unwrap();
    c.send(body).await.unwrap();
    c.send(b"\r\n.\r\n").await.unwrap();
    c.read_reply().await.unwrap()
}

#[tokio::test]
async fn a_body_containing_a_nul_is_refused_and_never_delivered() {
    // A NUL truncates the message for every parser written in C and is an
    // ordinary octet to the rest, so relaying one launders a difference: what
    // Pigeon signs is not what the receiver reads. Refused at the end of DATA,
    // which is still before the `250`, so the message stays the upstream MTA's
    // to report on.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    let (code, text) = submit_body(addr, b"Subject: hi\r\n\r\nbo\0dy").await;
    assert_eq!(code, 554, "a NUL body was not refused permanently: {text}");
    assert_eq!(sink.count(), 0, "a malformed message reached the sink");
}

#[tokio::test]
async fn a_refused_body_does_not_poison_the_next_message() {
    // The transaction is cleared on every outcome, so a refusal must not leave
    // the connection unusable or the envelope half-populated.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();
    c.send(b"EHLO sender.test\r\n").await.unwrap();
    c.read_reply().await.unwrap();

    for (body, want) in [(&b"a\0b"[..], 554u16), (&b"clean"[..], 250)] {
        c.send(b"MAIL FROM:<a@sender.test>\r\n").await.unwrap();
        assert_eq!(c.read_reply().await.unwrap().0, 250);
        c.send(b"RCPT TO:<hello@example.net>\r\n").await.unwrap();
        assert_eq!(c.read_reply().await.unwrap().0, 250);
        c.send(b"DATA\r\n").await.unwrap();
        assert_eq!(c.read_reply().await.unwrap().0, 354);
        c.send(b"Subject: hi\r\n\r\n").await.unwrap();
        c.send(body).await.unwrap();
        c.send(b"\r\n.\r\n").await.unwrap();
        let (code, text) = c.read_reply().await.unwrap();
        assert_eq!(code, want, "{text}");
    }

    assert_eq!(sink.count(), 1, "the clean message was not delivered");
}

#[tokio::test]
async fn an_overlong_body_line_is_relayed_rather_than_refused() {
    // A deliberate non-refusal. RFC 5321 §4.5.3.1.6 caps a line at 1000 octets,
    // but senders exceed it routinely — unwrapped base64, a pasted URL — and
    // relays accept it. Refusing would reject deliverable mail that every other
    // MTA carries; the receiver at the far end is the one entitled to object,
    // and if it does, the failure is reported through a DSN rather than
    // guessed at here.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(sink.clone(), config()).await;

    let long = "x".repeat(5000);
    let (code, text) = submit_body(addr, format!("Subject: hi\r\n\r\n{long}").as_bytes()).await;
    assert_eq!(code, 250, "an overlong line was refused: {text}");
    assert_eq!(sink.count(), 1);
}

#[tokio::test]
async fn a_session_cannot_be_held_open_for_ever_by_staying_busy() {
    // The per-command timeout resets on every command, so a client sending
    // NOOP every few seconds never idles out. With a connection cap in place
    // that turns the cap into the means of denial rather than the defence
    // against it, which is what `max_session` exists to stop.
    let sink = LocalOnly::new(&["example.net"]);
    let addr = start(
        sink,
        ServerConfig {
            max_session: Duration::from_millis(300),
            ..config()
        },
    )
    .await;

    let mut c = RawClient::connect(addr).await.unwrap();
    c.read_reply().await.unwrap();

    // Busy, never idle: a command every 50ms, well inside the command timeout.
    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if c.send(b"NOOP\r\n").await.is_err() {
                return true;
            }
            match c.read_reply().await {
                Some((421, _)) => return true,
                Some(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                // The server hung up rather than answering, which is the other
                // way a lifetime cap can end a session.
                None => return true,
            }
        }
    })
    .await;

    assert!(
        ended.unwrap_or(false),
        "a busy session outlived its maximum lifetime"
    );
}
