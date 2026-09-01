//! The anti-open-relay matrix.
//!
//! `SECURITY.md` calls this release-blocking, and it is the one property whose
//! failure is not a bug in Pigeon but a bug in the internet's mail: an open
//! relay is used within hours, and the address it is used from is the
//! operator's.
//!
//! The matrix has two axes — whether the sender authenticated, and whether the
//! recipient is a domain this host carries. Milestone 0 tested the
//! unauthenticated half against the MX listener. This is the other half: the
//! submission listener, where authentication exists and where getting it wrong
//! is exactly how relays are left open.
//!
//! | | recipient carried | recipient elsewhere |
//! |---|---|---|
//! | **unauthenticated** | accept (that is the MX's job) | **refuse** |
//! | **authenticated** | accept | accept — that is submission |
//!
//! The one cell that must never be "accept" is unauthenticated relay to
//! elsewhere. Everything below exists to hold that cell.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use pigeon_smtp::{Connection, DataError, Envelope, Message, MessageSink, Recipient, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A sink that accepts anything it is asked to, so the *server* is what is
/// under test.
///
/// Deliberately permissive: if the policy lived here, this suite would be
/// testing the fixture. What must refuse an unauthenticated relay is the
/// session's `require_auth`, and a sink that says yes to everything is how that
/// is proved.
#[derive(Clone, Default)]
struct Permissive {
    accepted: Arc<Mutex<Vec<Envelope>>>,
    /// The credential the fixture will accept, if any.
    credential: Option<(String, String)>,
}

impl MessageSink for Permissive {
    type Transaction = Option<String>;

    fn begin(
        &self,
        _peer: SocketAddr,
        _sender: &str,
        principal: Option<&str>,
    ) -> Self::Transaction {
        principal.map(str::to_string)
    }

    async fn authenticate(&self, username: &str, password: &str) -> Option<String> {
        match &self.credential {
            Some((u, p)) if u == username && p == password => Some(username.to_string()),
            _ => None,
        }
    }

    async fn accepts_recipient(
        &self,
        _txn: &mut Self::Transaction,
        _address: &str,
        _accepted: &[String],
    ) -> Recipient {
        Recipient::Accept
    }

    async fn deliver(
        &self,
        _txn: Self::Transaction,
        message: Message,
    ) -> Result<String, DataError> {
        self.accepted.lock().unwrap().push(message.envelope);
        Ok("OK".into())
    }

    async fn accepts_connection(&self, _peer: SocketAddr) -> Connection {
        Connection::Accept
    }
}

/// A self-signed certificate, so the submission listener can require TLS.
struct Material {
    dir: std::path::PathBuf,
    certificate: std::path::PathBuf,
    private_key: std::path::PathBuf,
    der: Vec<u8>,
}

impl Material {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pigeon-relay-{tag}-{}", std::process::id()));
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

    fn client(&self) -> Arc<rustls::ClientConfig> {
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

async fn start(sink: Permissive, config: ServerConfig) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = pigeon_smtp::serve(listener, config, sink).await;
    });
    addr
}

/// Minimal line-oriented client, over plaintext or TLS.
struct Client<S> {
    stream: S,
    buffered: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Client<S> {
    async fn send(&mut self, line: &str) -> Option<(u16, String)> {
        self.stream.write_all(line.as_bytes()).await.ok()?;
        self.reply().await
    }

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
                self.buffered.drain(..consumed);
                return Some((code, text[..consumed].to_string()));
            }
        }
        None
    }
}

/// Connect, greet, upgrade, greet again.
async fn tls_client(
    addr: SocketAddr,
    material: &Material,
) -> Client<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut plain = Client {
        stream: tokio::net::TcpStream::connect(addr).await.unwrap(),
        buffered: Vec::new(),
    };
    assert_eq!(plain.reply().await.unwrap().0, 220);
    plain.send("EHLO client.test\r\n").await.unwrap();
    assert_eq!(plain.send("STARTTLS\r\n").await.unwrap().0, 220);

    let tls = tokio_rustls::TlsConnector::from(material.client())
        .connect(
            rustls_pki_types::ServerName::try_from("mx.test").unwrap(),
            plain.stream,
        )
        .await
        .expect("handshake");

    let mut c = Client {
        stream: tls,
        buffered: Vec::new(),
    };
    assert_eq!(c.send("EHLO client.test\r\n").await.unwrap().0, 250);
    c
}

fn submission(material: &Material) -> ServerConfig {
    ServerConfig {
        hostname: "mx.test".into(),
        require_auth: true,
        tls: Some(pigeon_smtp::tls::Serving::new(
            pigeon_smtp::tls::load(&material.certificate, &material.private_key).unwrap(),
        )),
        ..Default::default()
    }
}

// ------------------------------------------------------- the load-bearing cell

#[tokio::test]
async fn submission_refuses_an_unauthenticated_transaction() {
    // The cell that must never be "accept". A permissive sink says yes to every
    // recipient, so what refuses here is the listener itself — which is the
    // point: policy that lives in the sink is policy a second sink can forget.
    let material = Material::new("unauth");
    let sink = Permissive::default();
    let addr = start(sink.clone(), submission(&material)).await;

    let mut c = tls_client(addr, &material).await;
    let (code, text) = c
        .send("MAIL FROM:<anyone@elsewhere.test>\r\n")
        .await
        .unwrap();

    assert_eq!(
        code, 530,
        "an unauthenticated transaction was accepted: {text}"
    );
    assert!(
        sink.accepted.lock().unwrap().is_empty(),
        "an unauthenticated message reached the sink"
    );
}

#[tokio::test]
async fn submission_refuses_a_wrong_credential_and_then_the_transaction() {
    let material = Material::new("wrong");
    let sink = Permissive {
        credential: Some(("alice".into(), "right".into())),
        ..Permissive::default()
    };
    let addr = start(sink.clone(), submission(&material)).await;

    let mut c = tls_client(addr, &material).await;
    // base64 of "\0alice\0wrong"
    let (code, _) = c.send("AUTH PLAIN AGFsaWNlAHdyb25n\r\n").await.unwrap();
    assert_eq!(code, 535);

    let (code, _) = c
        .send("MAIL FROM:<anyone@elsewhere.test>\r\n")
        .await
        .unwrap();
    assert_eq!(code, 530, "a failed login still opened a transaction");
}

#[tokio::test]
async fn submission_relays_for_an_authenticated_sender() {
    // The other half of the matrix: once authenticated, relaying anywhere is
    // the entire purpose of the port.
    let material = Material::new("authed");
    let sink = Permissive {
        credential: Some(("alice".into(), "secret".into())),
        ..Permissive::default()
    };
    let addr = start(sink.clone(), submission(&material)).await;

    let mut c = tls_client(addr, &material).await;
    // base64 of "\0alice\0secret"
    assert_eq!(
        c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
            .await
            .unwrap()
            .0,
        235
    );
    assert_eq!(
        c.send("MAIL FROM:<alice@example.com>\r\n").await.unwrap().0,
        250
    );
    assert_eq!(
        c.send("RCPT TO:<someone@elsewhere.test>\r\n")
            .await
            .unwrap()
            .0,
        250
    );
    assert_eq!(c.send("DATA\r\n").await.unwrap().0, 354);
    assert_eq!(
        c.send("Subject: hi\r\n\r\nbody\r\n.\r\n").await.unwrap().0,
        250
    );

    let accepted = sink.accepted.lock().unwrap();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].recipients, vec!["someone@elsewhere.test"]);
}

#[tokio::test]
async fn credentials_are_refused_before_tls() {
    // A client that sends its password in the clear has already given it away,
    // whatever the server does next — so the server refuses, and does not
    // advertise the mechanism either.
    let material = Material::new("cleartext");
    let sink = Permissive {
        credential: Some(("alice".into(), "secret".into())),
        ..Permissive::default()
    };
    let addr = start(sink, submission(&material)).await;

    let mut c = Client {
        stream: tokio::net::TcpStream::connect(addr).await.unwrap(),
        buffered: Vec::new(),
    };
    assert_eq!(c.reply().await.unwrap().0, 220);

    let (_, greeting) = c.send("EHLO client.test\r\n").await.unwrap();
    assert!(
        !greeting.contains("AUTH"),
        "AUTH was advertised before TLS: {greeting}"
    );
    assert_eq!(
        c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
            .await
            .unwrap()
            .0,
        538
    );
}

#[tokio::test]
async fn a_reset_does_not_deauthenticate() {
    // `RSET` clears the transaction, not the session. A client that reset and
    // then had to log in again would be a client that logs in per message —
    // and each login costs this server an Argon2 verification.
    let material = Material::new("rset");
    let sink = Permissive {
        credential: Some(("alice".into(), "secret".into())),
        ..Permissive::default()
    };
    let addr = start(sink, submission(&material)).await;

    let mut c = tls_client(addr, &material).await;
    assert_eq!(
        c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
            .await
            .unwrap()
            .0,
        235
    );
    assert_eq!(
        c.send("MAIL FROM:<alice@example.com>\r\n").await.unwrap().0,
        250
    );
    assert_eq!(c.send("RSET\r\n").await.unwrap().0, 250);
    assert_eq!(
        c.send("MAIL FROM:<alice@example.com>\r\n").await.unwrap().0,
        250,
        "RSET dropped the authentication"
    );
}

#[tokio::test]
async fn the_mx_listener_does_not_offer_authentication_at_all() {
    // Port 25 must not: a relay that authenticated on the MX port would be a
    // second way in, with no reason to exist and one more thing to get wrong.
    let material = Material::new("mx");
    let sink = Permissive {
        credential: Some(("alice".into(), "secret".into())),
        ..Permissive::default()
    };
    let addr = start(
        sink,
        ServerConfig {
            hostname: "mx.test".into(),
            tls: Some(pigeon_smtp::tls::Serving::new(
                pigeon_smtp::tls::load(&material.certificate, &material.private_key).unwrap(),
            )),
            ..Default::default()
        },
    )
    .await;

    let mut c = tls_client(addr, &material).await;
    let (_, greeting) = c.send("EHLO client.test\r\n").await.unwrap();
    assert!(!greeting.contains("AUTH"), "{greeting}");
    assert_eq!(
        c.send("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
            .await
            .unwrap()
            .0,
        500
    );
}
