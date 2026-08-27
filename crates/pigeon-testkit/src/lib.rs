//! Test harness shared across the workspace. Not published.
//!
//! # Why this does not depend on `pigeon-smtp`
//!
//! A harness that shares an implementation with the code under test cannot
//! catch that implementation being wrong. If the peer used the same codec to
//! find an end-of-data marker, a codec that looked for the wrong bytes would
//! agree with itself and both would pass.
//!
//! So the peer parses lines and scans for the terminator itself, in a few
//! obvious lines that are easy to eyeball. It depends on tokio and nothing
//! else.
//!
//! # What it is for
//!
//! Chiefly the delivery client, which is otherwise only ever tested against
//! Pigeon's own well-behaved server. Real receiving servers reject `EHLO`,
//! answer 4xx under load, hang up mid-reply, and occasionally emit nonsense —
//! and the client's response to each decides whether a message is retried,
//! bounced, or lost.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One action in a scripted conversation.
#[derive(Debug, Clone)]
enum Step {
    /// Write a line to the client, appending CRLF.
    Send(String),
    /// Write raw bytes, exactly as given.
    SendRaw(Vec<u8>),
    /// Read one line and record it.
    ReadLine,
    /// Read until the end-of-data marker and record the body.
    ReadBody,
    /// Do nothing for a while, to provoke a client timeout.
    Stall(Duration),
    /// Close the connection.
    Close,
}

/// Everything the client sent, in order.
#[derive(Debug, Clone, Default)]
pub struct Transcript(Arc<Mutex<Vec<String>>>);

impl Transcript {
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    /// Whether any recorded line starts with `prefix`, ignoring case.
    pub fn saw(&self, prefix: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.len() >= prefix.len() && l[..prefix.len()].eq_ignore_ascii_case(prefix))
    }

    fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }
}

/// A scripted SMTP server that does exactly what it is told, including things
/// no correct server would do.
#[derive(Debug, Clone, Default)]
pub struct Peer {
    steps: Vec<Step>,
}

impl Peer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Send a reply line. CRLF is appended.
    pub fn send(mut self, line: &str) -> Self {
        self.steps.push(Step::Send(line.to_string()));
        self
    }

    /// Send bytes verbatim, for replies that should be malformed.
    pub fn send_raw(mut self, bytes: &[u8]) -> Self {
        self.steps.push(Step::SendRaw(bytes.to_vec()));
        self
    }

    /// Read one command line from the client.
    pub fn read_line(mut self) -> Self {
        self.steps.push(Step::ReadLine);
        self
    }

    /// Read a message body, up to and including the terminator.
    pub fn read_body(mut self) -> Self {
        self.steps.push(Step::ReadBody);
        self
    }

    /// Go silent. Used to check that the client gives up rather than hanging.
    pub fn stall(mut self, d: Duration) -> Self {
        self.steps.push(Step::Stall(d));
        self
    }

    /// Hang up, possibly mid-conversation.
    pub fn close(mut self) -> Self {
        self.steps.push(Step::Close);
        self
    }

    /// A server that accepts everything, for tests about something else.
    pub fn accepting() -> Self {
        Self::new()
            .send("220 test.invalid ESMTP")
            .read_line() // EHLO
            .send("250-test.invalid")
            .send("250 8BITMIME")
            .read_line() // MAIL FROM
            .send("250 Ok")
            .read_line() // RCPT TO
            .send("250 Ok")
            .read_line() // DATA
            .send("354 Go ahead")
            .read_body()
            .send("250 Ok: queued as TESTPEER")
            .read_line() // QUIT
            .send("221 Bye")
            .close()
    }

    /// Bind an ephemeral port and run the script against one connection.
    ///
    /// Returns immediately with the address and a transcript that fills in as
    /// the client talks.
    pub async fn spawn(self) -> (SocketAddr, Transcript) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let transcript = Transcript::default();
        let recorder = transcript.clone();

        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffered: Vec<u8> = Vec::new();

            for step in self.steps {
                match step {
                    Step::Send(line) => {
                        if stream
                            .write_all(format!("{line}\r\n").as_bytes())
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Step::SendRaw(bytes) => {
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                    Step::ReadLine => match read_until(&mut stream, &mut buffered, b"\n").await {
                        Some(line) => {
                            recorder.push(String::from_utf8_lossy(&line).trim().to_string())
                        }
                        None => return,
                    },
                    Step::ReadBody => {
                        // Scanned here rather than by the codec under test, so
                        // a codec that looked for the wrong bytes could not
                        // agree with itself.
                        match read_until(&mut stream, &mut buffered, b"\r\n.\r\n").await {
                            Some(body) => recorder.push(String::from_utf8_lossy(&body).to_string()),
                            None => return,
                        }
                    }
                    Step::Stall(d) => tokio::time::sleep(d).await,
                    Step::Close => {
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
            }
        });

        (addr, transcript)
    }
}

/// Read until `marker` appears, returning everything up to and including it.
///
/// `buffered` carries bytes between calls, because a client that pipelines will
/// have sent the next command already.
async fn read_until(
    stream: &mut tokio::net::TcpStream,
    buffered: &mut Vec<u8>,
    marker: &[u8],
) -> Option<Vec<u8>> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = find(buffered, marker) {
            let end = at + marker.len();
            let out: Vec<u8> = buffered[..end].to_vec();
            buffered.drain(..end);
            return Some(out);
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A client that does exactly what it is told, including things no correct
/// client would do.
///
/// The counterpart to [`Peer`]. Where that one tests Pigeon's delivery client
/// against hostile servers, this tests Pigeon's server against hostile clients:
/// abrupt disconnects, silence, and connections opened only to be held.
///
/// These are what the server's limits exist for, and until something exercises
/// them they are defensive code that has never been shown to defend anything —
/// which is worse than absent, because the configuration field reads as
/// protection you do not actually have.
pub struct RawClient {
    stream: tokio::net::TcpStream,
    buffered: Vec<u8>,
}

impl RawClient {
    pub async fn connect(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            stream: tokio::net::TcpStream::connect(addr).await?,
            buffered: Vec::new(),
        })
    }

    /// Write bytes verbatim. Nothing is appended, so partial commands are
    /// possible.
    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await
    }

    /// Read one complete reply, following continuation lines.
    ///
    /// Returns `None` if the connection closed first.
    pub async fn read_reply(&mut self) -> Option<(u16, String)> {
        loop {
            if let Some(reply) = self.take_reply() {
                return Some(reply);
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buffered.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Read a reply, giving up after `limit`.
    ///
    /// `None` means nothing arrived — which is the assertion when checking that
    /// a connection is being held back by a limit.
    pub async fn read_reply_within(&mut self, limit: Duration) -> Option<(u16, String)> {
        tokio::time::timeout(limit, self.read_reply())
            .await
            .ok()
            .flatten()
    }

    /// Whether the server has closed the connection.
    pub async fn is_closed(&mut self, within: Duration) -> bool {
        let mut chunk = [0u8; 1];
        matches!(
            tokio::time::timeout(within, self.stream.read(&mut chunk)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    /// Drop the connection without warning, mid-command if you like.
    pub fn disconnect(self) {
        drop(self);
    }

    fn take_reply(&mut self) -> Option<(u16, String)> {
        let mut from = 0usize;
        loop {
            let nl = find(&self.buffered[from..], b"\n")? + from;
            let line = String::from_utf8_lossy(&self.buffered[from..=nl]).into_owned();
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();

            // A space after the code ends the reply; a hyphen continues it.
            if trimmed.as_bytes().get(3).copied().unwrap_or(b' ') != b'-' {
                let code = trimmed.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
                let whole = String::from_utf8_lossy(&self.buffered[..=nl]).into_owned();
                self.buffered.drain(..=nl);
                return Some((code, whole));
            }
            from = nl + 1;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_markers() {
        assert_eq!(find(b"hello\r\n", b"\r\n"), Some(5));
        assert_eq!(find(b"a\r\n.\r\n", b"\r\n.\r\n"), Some(1));
        assert_eq!(find(b"nothing", b"\r\n"), None);
        assert_eq!(find(b"ab", b"abc"), None);
    }

    #[test]
    fn transcript_matches_case_insensitively() {
        let t = Transcript::default();
        t.push("EHLO client.test".into());
        assert!(t.saw("ehlo"));
        assert!(t.saw("EHLO client"));
        assert!(!t.saw("HELO"));
    }
}
