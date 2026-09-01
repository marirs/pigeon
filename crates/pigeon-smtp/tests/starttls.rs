//! The inbound upgrade, and the boundary it has to hold.
//!
//! The interesting property is not that TLS works — rustls's business — but
//! that **nothing crosses the upgrade**. A client that pipelines commands
//! behind `STARTTLS` has put them in the server's buffer, in plaintext, before
//! any handshake happened; executing them afterwards would attribute an
//! injected command to the encrypted session. That is the injection half of
//! CVE-2011-0411, and it is a property of this server's buffer handling rather
//! than of the TLS library.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use pigeon_smtp::{DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Records what it was asked to accept, so a test can ask who got through.
#[derive(Clone, Default)]
struct Recorder {
    received: Arc<Mutex<Vec<Envelope>>>,
    /// The trace header the server wrote, which records whether the hop was
    /// encrypted.
    traces: Arc<Mutex<Vec<String>>>,
}

impl MessageSink for Recorder {
    type Transaction = ();

    fn begin(&self, _peer: std::net::SocketAddr, _sender: &str, _principal: Option<&str>) {}

    async fn accepts_recipient(
        &self,
        _txn: &mut (),
        address: &str,
        _accepted: &[String],
    ) -> Recipient {
        if address.ends_with("@example.net") {
            Recipient::Accept
        } else {
            Recipient::Reject
        }
    }

    async fn deliver(&self, _txn: (), message: Message) -> Result<String, DataError> {
        self.received.lock().unwrap().push(message.envelope);
        self.traces.lock().unwrap().push(message.received);
        Ok("OK".into())
    }
}

/// A self-signed certificate for `mx.test`, and the client trust anchor for it.
struct Material {
    dir: std::path::PathBuf,
    certificate: std::path::PathBuf,
    private_key: std::path::PathBuf,
    der: Vec<u8>,
}

impl Material {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pigeon-starttls-{tag}-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let generated = rcgen::generate_simple_self_signed(vec!["mx.test".into()]).unwrap();
        let certificate = dir.join("cert.pem");
        let private_key = dir.join("key.pem");
        std::fs::write(&certificate, generated.cert.pem()).unwrap();
        std::fs::write(&private_key, generated.signing_key.serialize_pem()).unwrap();

        Self {
            dir,
            certificate,
            private_key,
            der: generated.cert.der().to_vec(),
        }
    }

    fn server_config(&self) -> ServerConfig {
        ServerConfig {
            hostname: "mx.test".into(),
            tls: Some(pigeon_smtp::tls::Serving::new(
                pigeon_smtp::tls::load(&self.certificate, &self.private_key).unwrap(),
            )),
            ..Default::default()
        }
    }

    /// A client that trusts exactly this certificate and nothing else.
    fn client_config(&self) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(self.der.clone()))
            .unwrap();

        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }
}

impl Drop for Material {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start(sink: Recorder, config: ServerConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = pigeon_smtp::serve(listener, config, sink).await;
    });
    addr
}

/// A connection that can be spoken to before and after the handshake.
///
/// Deliberately hand-rolled rather than added to `pigeon-testkit`: a TLS client
/// there would put rustls in every test binary that uses the kit, for one file
/// that needs it.
struct Client<S> {
    stream: S,
    buffered: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Client<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    /// Read one complete reply, following continuation lines. `None` on close.
    async fn reply(&mut self) -> Option<(u16, String)> {
        loop {
            if let Some(r) = self.take() {
                return Some(r);
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buffered.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn take(&mut self) -> Option<(u16, String)> {
        let text = String::from_utf8_lossy(&self.buffered).to_string();
        let mut consumed = 0;
        for line in text.split_inclusive("\r\n") {
            consumed += line.len();
            let trimmed = line.trim_end();
            if trimmed.len() >= 4 && trimmed.as_bytes()[3] == b'-' {
                continue;
            }
            if trimmed.len() >= 3 {
                let code = trimmed[..3].parse().ok()?;
                let full = text[..consumed].to_string();
                self.buffered.drain(..consumed);
                return Some((code, full));
            }
        }
        None
    }
}

/// Connect, greet, and stop just before `STARTTLS`.
async fn greeted(addr: SocketAddr) -> Client<tokio::net::TcpStream> {
    let mut c = Client::new(tokio::net::TcpStream::connect(addr).await.unwrap());
    assert_eq!(c.reply().await.unwrap().0, 220);
    c.send(b"EHLO client.test\r\n").await;
    c
}

#[tokio::test]
async fn starttls_is_advertised_only_when_there_is_something_to_upgrade_to() {
    // The advertisement is a promise. Announcing STARTTLS with nothing behind
    // it would have the server answer `220 Ready` and then read the client's
    // handshake as SMTP commands — a downgrade that looks like an encrypted
    // session from the outside.
    let material = Material::new("advertised");

    let with = start(Recorder::default(), material.server_config()).await;
    let mut c = greeted(with).await;
    let (code, text) = c.reply().await.unwrap();
    assert_eq!(code, 250);
    assert!(text.contains("STARTTLS"), "not advertised: {text}");

    let without = start(
        Recorder::default(),
        ServerConfig {
            hostname: "mx.test".into(),
            ..Default::default()
        },
    )
    .await;
    let mut c = greeted(without).await;
    let (_, text) = c.reply().await.unwrap();
    assert!(
        !text.contains("STARTTLS"),
        "advertised with no certificate: {text}"
    );
}

#[tokio::test]
async fn the_upgrade_resets_the_session_and_requires_a_fresh_ehlo() {
    // Everything learned before the handshake was learned from an
    // unauthenticated conversation, so none of it survives — including the
    // client's greeting.
    let material = Material::new("reset");
    let addr = start(Recorder::default(), material.server_config()).await;

    let mut c = greeted(addr).await;
    c.reply().await.unwrap();
    c.send(b"STARTTLS\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 220);

    let tls = tokio_rustls::TlsConnector::from(material.client_config())
        .connect(
            rustls_pki_types::ServerName::try_from("mx.test").unwrap(),
            c.stream,
        )
        .await
        .expect("the handshake should succeed");
    let mut c = Client::new(tls);

    // The greeting is forgotten, so a command that needs one is out of
    // sequence.
    c.send(b"MAIL FROM:<a@sender.test>\r\n").await;
    assert_eq!(
        c.reply().await.unwrap().0,
        503,
        "the session remembered a greeting from before the handshake"
    );

    c.send(b"EHLO client.test\r\n").await;
    let (code, text) = c.reply().await.unwrap();
    assert_eq!(code, 250);
    // Not offered twice: a second upgrade inside the first is not a thing.
    assert!(
        !text.contains("STARTTLS"),
        "STARTTLS advertised inside TLS: {text}"
    );
}

#[tokio::test]
async fn plaintext_pipelined_behind_starttls_never_runs_in_the_encrypted_session() {
    // The load-bearing one. The injected commands are already in the server's
    // buffer when the handshake begins; executing them afterwards would let
    // anyone who can write plaintext to the socket have their envelope
    // attributed to the encrypted session.
    let material = Material::new("injection");
    let sink = Recorder::default();
    let addr = start(sink.clone(), material.server_config()).await;

    let mut c = greeted(addr).await;
    c.reply().await.unwrap();

    // One write: the upgrade request and an entire injected transaction.
    c.send(b"STARTTLS\r\nMAIL FROM:<injected@sender.test>\r\nRCPT TO:<injected@example.net>\r\n")
        .await;
    assert_eq!(c.reply().await.unwrap().0, 220);

    let tls = tokio_rustls::TlsConnector::from(material.client_config())
        .connect(
            rustls_pki_types::ServerName::try_from("mx.test").unwrap(),
            c.stream,
        )
        .await
        .expect("the handshake should succeed");
    let mut c = Client::new(tls);

    // A complete, legitimate transaction inside TLS.
    c.send(b"EHLO client.test\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 250);
    c.send(b"MAIL FROM:<real@sender.test>\r\n").await;
    assert_eq!(
        c.reply().await.unwrap().0,
        250,
        "the injected MAIL FROM was executed: a second one should have been refused"
    );
    c.send(b"RCPT TO:<real@example.net>\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 250);
    c.send(b"DATA\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 354);
    c.send(b"Subject: hi\r\n\r\nbody\r\n.\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 250);

    let received = sink.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1, "more than one message was accepted");
    assert_eq!(
        received[0].sender, "real@sender.test",
        "the injected sender reached the encrypted session"
    );
    assert_eq!(
        received[0].recipients,
        vec!["real@example.net".to_string()],
        "an injected recipient survived the upgrade"
    );
}

#[tokio::test]
async fn a_failed_handshake_does_not_fall_back_to_plaintext() {
    // The client was told `220` and believes everything it sends next is
    // encrypted. Reading it as commands would be reading a would-be encrypted
    // conversation in the clear.
    let material = Material::new("failed");
    let sink = Recorder::default();
    let addr = start(sink.clone(), material.server_config()).await;

    let mut c = greeted(addr).await;
    c.reply().await.unwrap();
    c.send(b"STARTTLS\r\n").await;
    assert_eq!(c.reply().await.unwrap().0, 220);

    // Not a ClientHello. A plaintext transaction, which the server must not
    // answer.
    c.send(b"MAIL FROM:<a@sender.test>\r\nRCPT TO:<a@example.net>\r\nDATA\r\n")
        .await;

    // Promptly, not eventually: a server that keeps the connection open is one
    // still waiting to be told something in a conversation it agreed to
    // encrypt, and the failure would otherwise hide behind the command timeout.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(2), c.reply()).await;
    match ended {
        Ok(None) => {}
        Ok(Some((code, text))) => {
            panic!("the server answered plaintext after agreeing to upgrade: {code} {text}")
        }
        Err(_) => panic!("the connection was left open after a failed handshake"),
    }
    assert!(
        sink.received.lock().unwrap().is_empty(),
        "a message was accepted over a connection that never negotiated TLS"
    );
}

// ------------------------------------------------------------------ outbound

/// Pigeon's delivery client talking to Pigeon's server, over TLS.
#[tokio::test]
async fn delivery_encrypts_when_the_peer_offers_it() {
    // Both halves in one test, which is the only way to exercise the upgrade
    // end to end without a real MTA: the server advertises STARTTLS, the client
    // takes it, and the message arrives over the encrypted connection.
    let material = Material::new("outbound");
    let sink = Recorder::default();
    let addr = start(sink.clone(), material.server_config()).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let envelope = pigeon_smtp::Envelope {
        sender: "a@sender.test".into(),
        recipients: vec!["hello@example.net".into()],
    };

    let accepted = pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"Subject: hi\r\n\r\nbody\r\n".as_slice()],
        Some(pigeon_smtp::client::Tls {
            config: pigeon_smtp::tls::outbound(),
            server_name: "mx.test",
        }),
    )
    .await
    .expect("the delivery should succeed");
    assert!(accepted.code == 250, "{accepted:?}");

    assert_eq!(sink.received.lock().unwrap().len(), 1);
    let trace = sink.traces.lock().unwrap()[0].clone();
    assert!(
        trace.contains("ESMTPS"),
        "the trace header does not record an encrypted hop: {trace}"
    );
}

#[tokio::test]
async fn a_failed_handshake_defers_rather_than_sending_in_the_clear() {
    // The downgrade this exists to prevent. An attacker who can make a
    // handshake fail — corrupting one packet is enough — could otherwise strip
    // encryption from every message by doing so, and a client that fell back
    // would hand them the plaintext for free.
    let (addr, transcript) = pigeon_testkit::Peer::new()
        .send("220 peer.test ESMTP")
        .read_line() // EHLO
        .send("250-peer.test")
        .send("250 STARTTLS")
        .read_line() // STARTTLS
        .send("220 Go ahead")
        // Not a ServerHello.
        .send_raw(b"certainly not a handshake\r\n")
        .close()
        .spawn()
        .await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let envelope = pigeon_smtp::Envelope {
        sender: "a@sender.test".into(),
        recipients: vec!["hello@example.net".into()],
    };

    let err = pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"Subject: hi\r\n\r\nbody\r\n".as_slice()],
        Some(pigeon_smtp::client::Tls {
            config: pigeon_smtp::tls::outbound(),
            server_name: "peer.test",
        }),
    )
    .await
    .expect_err("a failed handshake should not deliver");

    assert!(
        !err.is_permanent(),
        "a failed handshake bounced the message instead of deferring it: {err:?}"
    );
    assert!(
        !transcript.saw("MAIL FROM"),
        "the message was sent in the clear after the handshake failed: {:?}",
        transcript.lines()
    );
}

#[tokio::test]
async fn starttls_refused_after_being_advertised_defers() {
    // Same rule, one step earlier: the peer advertised it, so plaintext is no
    // longer on the table. A `454` here is a peer with a broken certificate,
    // which is usually fixed by the time the retry lands.
    // The peer stays willing to take the message in the clear after refusing
    // the upgrade, which is exactly the offer that must not be taken: a
    // conversation that ends here proves the client declined it rather than
    // simply losing the connection.
    let (addr, transcript) = pigeon_testkit::Peer::new()
        .send("220 peer.test ESMTP")
        .read_line() // EHLO
        .send("250-peer.test")
        .send("250 STARTTLS")
        .read_line() // STARTTLS
        .send("454 TLS not available right now")
        .read_line() // MAIL FROM, if the client is willing to go on
        .send("250 Ok")
        .read_line() // RCPT TO
        .send("250 Ok")
        .read_line() // DATA
        .send("354 Go ahead")
        .read_body()
        .send("250 Ok: queued")
        .read_line() // QUIT
        .send("221 Bye")
        .close()
        .spawn()
        .await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let envelope = pigeon_smtp::Envelope {
        sender: "a@sender.test".into(),
        recipients: vec!["hello@example.net".into()],
    };

    let err = pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"Subject: hi\r\n\r\nbody\r\n".as_slice()],
        Some(pigeon_smtp::client::Tls {
            config: pigeon_smtp::tls::outbound(),
            server_name: "peer.test",
        }),
    )
    .await
    .expect_err("a refused upgrade should not deliver");

    assert!(!err.is_permanent(), "{err:?}");
    assert!(
        !transcript.saw("MAIL FROM"),
        "the message was sent in the clear: {:?}",
        transcript.lines()
    );
}

#[tokio::test]
async fn a_peer_that_offers_nothing_is_still_delivered_to() {
    // Opportunistic means opportunistic. A server with no STARTTLS is the
    // majority of small mail hosts, and refusing them would be refusing to
    // deliver mail rather than protecting it.
    let (addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let envelope = pigeon_smtp::Envelope {
        sender: "a@sender.test".into(),
        recipients: vec!["hello@example.net".into()],
    };

    pigeon_smtp::deliver(
        stream,
        "client.test",
        &envelope,
        &[b"Subject: hi\r\n\r\nbody\r\n".as_slice()],
        Some(pigeon_smtp::client::Tls {
            config: pigeon_smtp::tls::outbound(),
            server_name: "peer.test",
        }),
    )
    .await
    .expect("a plaintext peer should still be delivered to");

    assert!(
        !transcript.saw("STARTTLS"),
        "STARTTLS was attempted against a peer that never offered it"
    );
}
