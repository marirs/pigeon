//! The listener and per-connection driver.
//!
//! This module deliberately contains no protocol knowledge. It reads bytes,
//! hands them to [`crate::codec`], passes the resulting commands to
//! [`crate::session`], and writes back whatever that decides. Every judgement
//! about what is legal lives in the pure modules, where it can be tested
//! without a socket.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::codec::{DataReader, LineError, LineReader};
use crate::command::{self, MAX_COMMAND_LINE};
use crate::reply::{self, Reply};
use crate::session::{Action, DataError, Message, Session, State};

/// What the server does with recipients and completed messages.
///
/// Recipient checking is synchronous because routing is an in-memory snapshot;
/// if it ever needs I/O, that snapshot has been designed wrong.
pub trait MessageSink: Clone + Send + Sync + 'static {
    /// Whether this address should be accepted at `RCPT TO`.
    ///
    /// Called before the sender transmits the body, which is the only point at
    /// which a message can be refused without Pigeon becoming responsible for
    /// bouncing it.
    fn accepts_recipient(&self, address: &str) -> bool;

    /// Take a complete message. The returned id appears in the `250`.
    ///
    /// Returning `Ok` is a promise that the message will survive a crash, so
    /// this must not return until it is durable.
    fn deliver(&self, message: Message) -> impl Future<Output = Result<String, DataError>> + Send;
}

/// Build the `Received:` header for a message.
///
/// RFC 5321 §4.4 requires one on everything relayed. It is also the only loop
/// guard that works across systems Pigeon cannot see: configuration-time
/// detection catches cycles among managed domains, but a message that leaves
/// and re-enters through somebody else's forwarder is invisible except as a
/// growing stack of these.
///
/// Safe for DKIM — a signature does not cover headers added above it.
fn received_header(hostname: &str, session: &Session, peer: SocketAddr, tls: bool) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let helo = session.peer_name().unwrap_or("unknown");
    let protocol = if tls { "ESMTPS" } else { "ESMTP" };

    // The `for` clause names a recipient only when there is exactly one.
    // Listing several would disclose each recipient's address to all the
    // others, which is a privacy leak the specification warns about.
    let for_clause = match session.envelope().recipients.as_slice() {
        [one] => format!("\r\n\tfor <{one}>"),
        _ => String::new(),
    };

    format!(
        "Received: from {helo} ([{ip}])\r\n\tby {hostname} with {protocol}{for_clause};\r\n\t{date}\r\n",
        ip = peer.ip(),
        date = pigeon_types::rfc5322_date(now),
    )
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Name used in the banner and EHLO response. Must match forward and
    /// reverse DNS or receiving systems will distrust everything sent.
    pub hostname: String,
    pub max_message_size: usize,
    /// How long to wait for a command before hanging up.
    pub command_timeout: Duration,
    /// How long to wait for more body bytes.
    pub data_timeout: Duration,
    /// Connections served at once. Beyond this, accepts wait rather than being
    /// refused, so a burst queues instead of bouncing.
    pub max_connections: usize,
    /// Longest a single connection may live, however busy it is.
    ///
    /// The per-command timeout resets on every command, so a client sending
    /// `NOOP` every few minutes holds its slot indefinitely. With a connection
    /// cap in place, enough such clients close the server to everyone else —
    /// the cap becomes the means of denial rather than the defence against it.
    pub max_session: Duration,
    /// Advertise STARTTLS. False until the TLS layer exists.
    pub tls_available: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            max_message_size: crate::DEFAULT_MAX_MESSAGE_SIZE,
            // RFC 5321 §4.5.3.2 sets five minutes as the floor for most
            // command timeouts. Shorter values break slow but legitimate
            // senders.
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(600),
            max_connections: 256,
            max_session: Duration::from_secs(3600),
            tls_available: false,
        }
    }
}

/// Serve until the process ends.
pub async fn serve<S: MessageSink>(
    listener: TcpListener,
    config: ServerConfig,
    sink: S,
) -> io::Result<()> {
    let config = Arc::new(config);
    let limit = Arc::new(Semaphore::new(config.max_connections));

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // Per-connection accept errors are transient: a peer that
                // vanished, or a momentarily exhausted fd table. Killing the
                // listener over one would turn a blip into an outage.
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };

        // Acquired before spawning so that backpressure applies to accepting,
        // not merely to work already in flight.
        let permit = match Arc::clone(&limit).acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // semaphore closed: shutting down
        };

        let config = Arc::clone(&config);
        let sink = sink.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, peer, config, sink).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }

    Ok(())
}

/// Whether the connection loop should keep going.
enum Flow {
    Continue,
    Stop,
}

/// Drive one connection.
async fn handle<S: MessageSink>(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    sink: S,
) -> io::Result<()> {
    let mut session =
        Session::new(config.hostname.clone(), config.tls_available, config.max_message_size);
    let mut lines = LineReader::new(MAX_COMMAND_LINE);
    let mut line = Vec::with_capacity(MAX_COMMAND_LINE);
    let mut chunk = vec![0u8; 8 * 1024];
    let mut data: Option<DataReader> = None;
    let started = Instant::now();

    tracing::debug!(%peer, "connection opened");
    write_reply(&mut stream, &session.greeting()).await?;

    loop {
        // Bound the whole conversation, not just each pause within it.
        let elapsed = started.elapsed();
        if elapsed >= config.max_session {
            tracing::debug!(%peer, "session lifetime exceeded");
            let _ = write_reply(&mut stream, &reply::session_too_long()).await;
            return Ok(());
        }
        let remaining = config.max_session - elapsed;

        let phase = if data.is_some() { config.data_timeout } else { config.command_timeout };
        let wait = phase.min(remaining);

        let n = match tokio::time::timeout(wait, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                tracing::debug!(%peer, "peer closed");
                return Ok(());
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Announce the timeout rather than vanishing, so the sender
                // logs a reason and retries instead of guessing.
                let _ = write_reply(&mut stream, &reply::timeout()).await;
                return Ok(());
            }
        };

        let mut input: &[u8] = &chunk[..n];

        // Finish any body in progress before treating bytes as commands.
        if data.is_some() {
            // Scoped so the mutable borrow ends before `data.take()`.
            let (used, complete) = {
                let reader = data.as_mut().expect("checked above");
                let (used, _) = reader.feed(input);
                (used, reader.is_complete())
            };
            if !complete {
                continue;
            }
            input = &input[used..];
            let reader = data.take().expect("checked above");
            if let Flow::Stop =
                finish_data(&mut stream, &mut session, &sink, &config, peer, reader).await?
            {
                return Ok(());
            }
        }

        lines.feed(input);

        loop {
            match lines.take_line(&mut line) {
                Ok(true) => {
                    match step(&mut stream, &mut session, &sink, &line).await? {
                        Step::Continue => {}
                        Step::Close => return Ok(()),
                        Step::BeginData => {
                            // A pipelining client may have sent body bytes in
                            // the same packet as DATA; they are buffered here,
                            // not on the socket.
                            let mut reader = DataReader::new(config.max_message_size);
                            let pending = lines.take_remaining();
                            let (used, _) = reader.feed(&pending);

                            if reader.is_complete() {
                                let rest = pending[used..].to_vec();
                                if let Flow::Stop = finish_data(
                                    &mut stream,
                                    &mut session,
                                    &sink,
                                    &config,
                                    peer,
                                    reader,
                                )
                                .await?
                                {
                                    return Ok(());
                                }
                                lines.feed(&rest);
                            } else {
                                data = Some(reader);
                                break;
                            }
                        }
                    }
                }
                Ok(false) => break,
                Err(LineError::TooLong) => {
                    let action = session.advance_parse_error(command::ParseError::TooLong);
                    if let Flow::Stop = emit(&mut stream, action).await? {
                        return Ok(());
                    }
                }
            }
        }
    }
}

enum Step {
    Continue,
    Close,
    BeginData,
}

/// Handle one framed command line.
async fn step<S: MessageSink>(
    stream: &mut TcpStream,
    session: &mut Session,
    sink: &S,
    line: &[u8],
) -> io::Result<Step> {
    let cmd = match command::parse(line) {
        Ok(c) => c,
        Err(e) => {
            let action = session.advance_parse_error(e);
            return match emit(stream, action).await? {
                Flow::Continue => Ok(Step::Continue),
                Flow::Stop => Ok(Step::Close),
            };
        }
    };

    // Recipient validation happens here rather than inside the session so the
    // state machine stays free of routing. Refusing at RCPT TO is the last
    // moment a message can be declined without Pigeon owning the bounce.
    // Only when RCPT is actually in sequence. Otherwise a mistimed RCPT would
    // be answered 550 "no such user" when the real fault is 503 "bad sequence",
    // which sends the operator looking for a routing problem that isn't there.
    if let command::Command::Rcpt { path, .. } = cmd
        && matches!(session.state(), State::Mail | State::Rcpt)
        && !sink.accepts_recipient(path)
    {
        tracing::debug!(recipient = %path, "recipient refused");
        write_reply(stream, &reply::no_such_user()).await?;
        return Ok(Step::Continue);
    }

    let action = session.advance(cmd);
    let begins_data = matches!(action, Action::ReadData(_));

    match emit(stream, action).await? {
        Flow::Stop => Ok(Step::Close),
        Flow::Continue if begins_data => Ok(Step::BeginData),
        Flow::Continue => Ok(Step::Continue),
    }
}

/// Hand a finished body to the sink and answer the client.
async fn finish_data<S: MessageSink>(
    stream: &mut TcpStream,
    session: &mut Session,
    sink: &S,
    config: &ServerConfig,
    peer: SocketAddr,
    reader: DataReader,
) -> io::Result<Flow> {
    let envelope = session.envelope().clone();
    let received = received_header(&config.hostname, session, peer, session.is_tls());
    let too_large = reader.is_too_large();
    let body = reader.into_body();

    let outcome = if too_large {
        Err(DataError::TooLarge)
    } else {
        sink.deliver(Message { envelope, received, body }).await
    };

    let action = session.data_received(outcome);
    emit(stream, action).await
}

/// Write whatever an action asked for, and say whether to keep going.
async fn emit(stream: &mut TcpStream, action: Action) -> io::Result<Flow> {
    match action {
        Action::Reply(r) | Action::ReadData(r) => {
            write_reply(stream, &r).await?;
            Ok(Flow::Continue)
        }
        Action::Close(r) => {
            write_reply(stream, &r).await?;
            let _ = stream.shutdown().await;
            Ok(Flow::Stop)
        }
        Action::StartTls(r) => {
            // Unreachable while tls_available is false: the session answers 454
            // before producing this. Kept explicit so that adding TLS is a
            // compile error here rather than a silent no-op.
            write_reply(stream, &r).await?;
            Ok(Flow::Continue)
        }
    }
}

async fn write_reply(stream: &mut TcpStream, r: &Reply) -> io::Result<()> {
    stream.write_all(r.to_wire().as_bytes()).await?;
    stream.flush().await
}
