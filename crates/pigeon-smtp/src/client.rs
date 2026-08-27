//! Outbound delivery.
//!
//! Takes an already-connected stream and conducts the sending side of the
//! conversation. Choosing *which* host to connect to is deliberately not here:
//! MX selection belongs to the DNS layer, and keeping it out means this module
//! is testable against an in-process server rather than the internet.
//!
//! # Why the error classification matters more than the happy path
//!
//! Every failure has to land on the right side of one line: retry, or give up
//! and bounce. Treating a permanent rejection as transient means retrying for
//! days against a mailbox that will never exist. Treating a transient failure
//! as permanent means bouncing mail that would have been delivered fifteen
//! minutes later — and since Pigeon keeps no copy, that mail is gone.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::session::Envelope;

/// Longest reply line accepted from a peer, to bound memory on a hostile one.
const MAX_REPLY_LINE: usize = 1024;

/// Most continuation lines accepted in one reply.
const MAX_REPLY_LINES: usize = 128;

// Every read is bounded. A peer that accepts a connection and then says nothing
// would otherwise hold a delivery task open forever — no error, no retry, just
// a task that never finishes and a message that never moves.
//
// The values follow RFC 5321 §4.5.3.2, whose minimums are generous on purpose:
// a receiving server may legitimately take minutes to accept a large message,
// and a client that gives up early turns someone else's slow disk into a bounce.

/// Waiting for the opening banner, and for replies to ordinary commands.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// Waiting for the final acknowledgement after the body has been sent. Longer,
/// because this is where the remote does its filtering and disk work.
const DATA_ACK_TIMEOUT: Duration = Duration::from_secs(600);

/// Sending the body. A peer that stops reading must not block us indefinitely.
const BODY_WRITE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// 4xx or a connection failure. Retry later; the message is still ours to
    /// deliver.
    Transient { code: u16, message: String },
    /// 5xx. The remote will never accept this message; bounce it.
    Permanent { code: u16, message: String },
    /// The peer stopped responding. Transient: a slow or overloaded server is
    /// the usual cause, and it is usually working again later.
    Timeout(&'static str),
    /// The peer is not speaking SMTP as expected.
    Protocol(String),
}

impl ClientError {
    /// Whether to stop trying. Retrying a permanent failure wastes days;
    /// bouncing a transient one loses mail Pigeon no longer has a copy of.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent { .. })
    }

    fn from_code(code: u16, message: String) -> Self {
        if code >= 500 {
            Self::Permanent { code, message }
        } else {
            Self::Transient { code, message }
        }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::Transient { code, message } => write!(f, "temporary failure {code}: {message}"),
            Self::Permanent { code, message } => write!(f, "permanent failure {code}: {message}"),
            Self::Timeout(phase) => write!(f, "timed out {phase}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// What the remote said about a delivered message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub code: u16,
    /// The remote's own text, worth keeping: it usually carries their queue id,
    /// which is the only handle you have when asking them what happened.
    pub message: String,
}

/// Conduct one delivery over an established connection.
///
/// `ehlo_name` must be a hostname whose forward and reverse DNS both resolve
/// back to the sending address. Receivers check, and a mismatch is one of the
/// cheapest ways to be treated as spam.
/// `parts` are written in sequence as one message, so a trace header and a body
/// can be sent without concatenating them first.
pub async fn deliver<S>(
    stream: S,
    ehlo_name: &str,
    envelope: &Envelope,
    parts: &[&[u8]],
) -> Result<Accepted, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut io = BufReader::new(stream);

    let (code, msg) = read_reply_within(&mut io, COMMAND_TIMEOUT, "waiting for greeting").await?;
    if code != 220 {
        return Err(ClientError::from_code(code, msg));
    }

    // HELO is the fallback for the rare server that rejects EHLO outright.
    // Losing ESMTP costs little here; failing the delivery costs the message.
    let (code, _) = command(&mut io, &format!("EHLO {ehlo_name}\r\n")).await?;
    if code != 250 {
        let (code, msg) = command(&mut io, &format!("HELO {ehlo_name}\r\n")).await?;
        if code != 250 {
            return Err(ClientError::from_code(code, msg));
        }
    }

    let from = &envelope.sender;
    let (code, msg) = command(&mut io, &format!("MAIL FROM:<{from}>\r\n")).await?;
    if code != 250 {
        return Err(ClientError::from_code(code, msg));
    }

    // Every recipient in the envelope is offered, and all must be accepted.
    // Partial acceptance is treated as failure of the whole delivery, because
    // succeeding for some and failing for others would leave the caller to
    // track which — and there is nowhere to record that yet. Splitting one
    // recipient per delivery belongs with the per-recipient queue in Milestone
    // 3, which is what makes partial outcomes representable.
    for rcpt in &envelope.recipients {
        let (code, msg) = command(&mut io, &format!("RCPT TO:<{rcpt}>\r\n")).await?;
        if !(200..300).contains(&code) {
            return Err(ClientError::from_code(code, msg));
        }
    }

    let (code, msg) = command(&mut io, "DATA\r\n").await?;
    if code != 354 {
        return Err(ClientError::from_code(code, msg));
    }

    match tokio::time::timeout(BODY_WRITE_TIMEOUT, async {
        write_dot_stuffed(io.get_mut(), parts).await?;
        io.get_mut().flush().await
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err(ClientError::Timeout("sending the message body")),
    }

    let (code, message) =
        read_reply_within(&mut io, DATA_ACK_TIMEOUT, "waiting for acknowledgement").await?;
    if code != 250 {
        return Err(ClientError::from_code(code, message));
    }

    // The message is already accepted; a failure saying goodbye is not a
    // delivery failure and must not cause a retry.
    let _ = command(&mut io, "QUIT\r\n").await;

    Ok(Accepted { code, message })
}

async fn command<S>(io: &mut BufReader<S>, line: &str) -> Result<(u16, String), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    io.get_mut().write_all(line.as_bytes()).await?;
    io.get_mut().flush().await?;
    read_reply_within(io, COMMAND_TIMEOUT, "waiting for a command reply").await
}

/// Read a reply, giving up after `limit`.
async fn read_reply_within<S>(
    io: &mut BufReader<S>,
    limit: Duration,
    phase: &'static str,
) -> Result<(u16, String), ClientError>
where
    S: AsyncRead + Unpin,
{
    match tokio::time::timeout(limit, read_reply(io)).await {
        Ok(r) => r,
        Err(_) => Err(ClientError::Timeout(phase)),
    }
}

/// Read one reply, following continuation lines.
async fn read_reply<S>(io: &mut BufReader<S>) -> Result<(u16, String), ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut text = String::new();
    let mut code: Option<u16> = None;

    for _ in 0..MAX_REPLY_LINES {
        let mut line = String::new();
        let n = read_line_capped(io, &mut line).await?;
        if n == 0 {
            return Err(ClientError::Protocol("connection closed mid-reply".into()));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);

        // Check the first three bytes are ASCII digits *before* slicing. A peer
        // sending a multi-byte character here would otherwise split it and
        // panic the delivery task — remote input must never do that.
        let raw = trimmed.as_bytes();
        if raw.len() < 3 || !raw[..3].iter().all(u8::is_ascii_digit) {
            return Err(ClientError::Protocol(format!("malformed reply line: {trimmed:?}")));
        }

        let this: u16 = trimmed[..3]
            .parse()
            .map_err(|_| ClientError::Protocol(format!("bad status code: {trimmed:?}")))?;

        match code {
            None => code = Some(this),
            // A reply whose code changes partway through is malformed, and
            // trusting either half of it would be a guess.
            Some(first) if first != this => {
                return Err(ClientError::Protocol(format!(
                    "reply code changed from {first} to {this}"
                )));
            }
            _ => {}
        }

        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(trimmed[3..].trim_start_matches(['-', ' ']));

        // A space after the code marks the last line; a hyphen means more.
        if trimmed.as_bytes().get(3).copied().unwrap_or(b' ') != b'-' {
            return Ok((code.unwrap_or(0), text));
        }
    }

    Err(ClientError::Protocol("reply had too many continuation lines".into()))
}

async fn read_line_capped<S>(io: &mut BufReader<S>, out: &mut String) -> Result<usize, ClientError>
where
    S: AsyncRead + Unpin,
{
    let mut taken = (&mut *io).take(MAX_REPLY_LINE as u64);

    let n = match taken.read_line(out).await {
        Ok(n) => n,
        // `read_line` reports non-UTF-8 input as an I/O error, but nothing is
        // wrong with the socket — the peer sent bytes that are not a reply.
        // Reporting it as I/O would send whoever reads the log looking at the
        // network instead of at the remote server.
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Err(ClientError::Protocol("reply was not valid UTF-8".into()));
        }
        Err(e) => return Err(ClientError::Io(e)),
    };

    if n == MAX_REPLY_LINE && !out.ends_with('\n') {
        return Err(ClientError::Protocol("reply line too long".into()));
    }
    Ok(n)
}

/// Write a body with dot-stuffing applied, then the end-of-data marker.
///
/// Spans between stuffed lines are written directly out of `body`, so a message
/// is not copied merely to add a handful of dots.
async fn write_dot_stuffed<W>(w: &mut W, parts: &[&[u8]]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut at_line_start = true;
    let mut last: Option<u8> = None;

    // Several parts, stuffed as though they were one stream. A trace header and
    // a body are written in sequence rather than concatenated first, so a large
    // message is never copied to prepend a few hundred bytes to it.
    for part in parts {
        let mut start = 0usize;
        for i in 0..part.len() {
            if at_line_start && part[i] == b'.' {
                // Emit through the dot, then a second one. A line beginning
                // with a dot would otherwise be read as the end of the message.
                w.write_all(&part[start..=i]).await?;
                w.write_all(b".").await?;
                start = i + 1;
            }
            at_line_start = part[i] == b'\n';
        }
        w.write_all(&part[start..]).await?;
        if let Some(&b) = part.last() {
            last = Some(b);
        }
    }

    // The terminator only counts at the start of a line, so an unterminated
    // final line needs one before it.
    match last {
        Some(b'\n') | None => {}
        Some(_) => w.write_all(b"\r\n").await?,
    }
    w.write_all(b".\r\n").await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn stuff(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_dot_stuffed(&mut out, &[body]).await.unwrap();
        out
    }

    async fn stuff_parts(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        write_dot_stuffed(&mut out, parts).await.unwrap();
        out
    }

    #[tokio::test]
    async fn parts_are_stuffed_as_one_stream() {
        // The boundary between parts is not a line boundary, so state has to
        // carry across it or a dot at the seam is missed.
        assert_eq!(
            stuff_parts(&[b"Received: x\r\n", b".hidden\r\n"]).await,
            b"Received: x\r\n..hidden\r\n.\r\n"
        );
        // A part ending mid-line must not make the next part look line-initial.
        assert_eq!(stuff_parts(&[b"no newline", b".still same line\r\n"]).await,
            b"no newline.still same line\r\n.\r\n");
    }

    #[tokio::test]
    async fn empty_parts_are_ignored() {
        assert_eq!(stuff_parts(&[b"", b"hi\r\n", b""]).await, b"hi\r\n.\r\n");
        assert_eq!(stuff_parts(&[]).await, b".\r\n");
    }

    #[tokio::test]
    async fn plain_body_gets_only_a_terminator() {
        assert_eq!(stuff(b"hello\r\n").await, b"hello\r\n.\r\n");
    }

    #[tokio::test]
    async fn leading_dot_is_doubled() {
        assert_eq!(stuff(b".hidden\r\n").await, b"..hidden\r\n.\r\n");
    }

    #[tokio::test]
    async fn only_line_initial_dots_are_doubled() {
        assert_eq!(stuff(b"version 1.0\r\n").await, b"version 1.0\r\n.\r\n");
    }

    #[tokio::test]
    async fn every_affected_line_is_stuffed() {
        assert_eq!(
            stuff(b".one\r\ntwo\r\n.three\r\n").await,
            b"..one\r\ntwo\r\n..three\r\n.\r\n"
        );
    }

    #[tokio::test]
    async fn a_lone_dot_line_would_not_terminate_early() {
        assert_eq!(stuff(b".\r\n").await, b"..\r\n.\r\n");
    }

    #[tokio::test]
    async fn missing_final_newline_is_supplied() {
        // Without this the terminator would not start at a line boundary.
        assert_eq!(stuff(b"no newline").await, b"no newline\r\n.\r\n");
    }

    #[tokio::test]
    async fn empty_body_is_just_the_terminator() {
        assert_eq!(stuff(b"").await, b".\r\n");
    }

    #[tokio::test]
    async fn stuffing_round_trips_through_the_reader() {
        // Whatever this writes, the receiving codec must recover exactly.
        use crate::codec::DataReader;
        for original in [
            &b"plain\r\n"[..],
            b".leading\r\n",
            b"..double\r\n",
            b".\r\n",
            b"a\r\n.\r\nb\r\n",
            b"mixed 1.0\r\n.dot\r\n",
        ] {
            let wire = stuff(original).await;
            let mut r = DataReader::new(1 << 20);
            r.feed(&wire);
            assert!(r.is_complete(), "no terminator for {original:?}");
            assert_eq!(r.body(), original, "round trip failed for {original:?}");
        }
    }

    #[test]
    fn classifies_by_status_class() {
        assert!(ClientError::from_code(550, "no such user".into()).is_permanent());
        assert!(!ClientError::from_code(451, "try later".into()).is_permanent());
        assert!(!ClientError::from_code(421, "shutting down".into()).is_permanent());
    }
}
