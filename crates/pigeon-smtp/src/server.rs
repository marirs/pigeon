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
    /// State pinned for one mail transaction.
    ///
    /// Created at `MAIL FROM` and handed back at delivery, so everything from
    /// the recipient decision to the signature is taken from one consistent
    /// view. Without it, a reload landing between `RCPT TO` and the end of
    /// `DATA` could accept a recipient under one configuration and forward it
    /// under another — accepting mail for a route that no longer exists, or
    /// signing with a key that has just been retired.
    ///
    /// `()` for a sink with nothing to pin.
    type Transaction: Send + Sync;

    /// Begin a transaction, pinning whatever must not change inside it.
    ///
    /// At `MAIL FROM` rather than at the first `RCPT TO`: earlier is safe,
    /// later is not, and this is the point at which the transaction exists.
    ///
    /// The peer and the accepted sender are handed over because a recipient
    /// decision can depend on both — greylisting is keyed on the pair together
    /// with the recipient — and re-deriving them at `RCPT` would mean two
    /// sources for one fact.
    fn begin(&self, peer: SocketAddr, sender: &str) -> Self::Transaction;

    /// Whether to serve this peer at all.
    ///
    /// Called once, before the banner. This is where a blocklist decision
    /// belongs: refusing here costs the sender one connection and this server
    /// one lookup, while refusing later has already paid for a conversation.
    ///
    /// The default serves everyone, so a sink with no opinion says nothing.
    fn accepts_connection(&self, peer: SocketAddr) -> impl Future<Output = Connection> + Send {
        let _ = peer;
        async { Connection::Accept }
    }

    /// Whether this address should be accepted at `RCPT TO`, and what
    /// accepting it means.
    ///
    /// Called before the sender transmits the body, which is the only point at
    /// which a message can be refused without Pigeon becoming responsible for
    /// bouncing it. `accepted` is what the envelope holds already, so a sink
    /// can refuse a combination it cannot handle as one message.
    ///
    /// The transaction is **mutable** because deciding a recipient is also
    /// resolving it: a sink that answers `Accept` here and works out where the
    /// address goes later would be routing twice, and the second answer can
    /// differ from the first. What is decided here is recorded here, and
    /// `deliver` consumes it.
    /// Asynchronous because a decision may need durable state: greylisting
    /// remembers that this triplet has been seen, and remembering it is a
    /// write.
    fn accepts_recipient(
        &self,
        transaction: &mut Self::Transaction,
        address: &str,
        accepted: &[String],
    ) -> impl Future<Output = Recipient> + Send;

    /// Take a complete message. The returned id appears in the `250`.
    ///
    /// Returning `Ok` is a promise that the message will survive a crash, so
    /// this must not return until it is durable.
    fn deliver(
        &self,
        transaction: Self::Transaction,
        message: Message,
    ) -> impl Future<Output = Result<String, DataError>> + Send;
}

/// Whether a peer is served at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Connection {
    Accept,
    /// Refused before the banner. The reason is sent to the peer, so it says
    /// what was decided without saying what would change the decision — reply
    /// text is attacker-visible, and a blocklist name is a hint about how to
    /// get around it.
    Refuse(String),
}

/// What to do with a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    Accept,
    /// No such user here, or nothing routes it. Permanent.
    Reject,
    /// Not in *this* transaction. Transient, so the sender retries the address
    /// in another one rather than treating it as undeliverable.
    ///
    /// Exists for combinations rather than addresses: a sink that can handle
    /// each of two recipients but not both at once has no permanent answer to
    /// give about either.
    Defer,
}

/// How long a single reply may take to write before the peer is assumed dead.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Trace headers tolerated before a message is treated as looping.
///
/// RFC 5321 §6.3 suggests counting `Received:` lines with a threshold around
/// this. Configuration-time loop detection covers cycles among domains Pigeon
/// manages; this covers the ones it cannot see, where a message leaves through
/// somebody else's forwarder and comes back.
pub const MAX_HOPS: usize = 100;

/// Count `Received:` headers at the top of a message.
///
/// Only the leading header block is examined, and scanning stops at the blank
/// line that ends it — a body mentioning `Received:` at the start of a line
/// must not be able to make a message look like it is looping.
fn count_hops(body: &[u8]) -> usize {
    let mut hops = 0;
    let mut at_line_start = true;
    let mut i = 0;

    while i < body.len() {
        if at_line_start {
            if body[i..].starts_with(b"\r\n") || body[i] == b'\n' {
                break; // end of the header block
            }
            if body[i..].len() >= 9 && body[i..i + 9].eq_ignore_ascii_case(b"Received:") {
                hops += 1;
            }
        }
        at_line_start = body[i] == b'\n';
        i += 1;
    }
    hops
}

/// Make a peer-supplied string safe to place inside a header.
///
/// Replaces anything that could end a line or a syntactic element. Truncated,
/// too: the greeting may be up to a full command line, and a trace header is
/// not the place for 500 bytes of attacker-chosen text.
fn sanitise_for_header(raw: &str) -> String {
    const MAX: usize = 128;
    let mut out: String = raw
        .chars()
        .take(MAX)
        .map(|c| match c {
            c if c.is_control() => '?',
            '(' | ')' | '<' | '>' | ';' | '\\' | '"' => '?',
            c => c,
        })
        .collect();
    if raw.chars().count() > MAX {
        out.push_str("...");
    }
    out
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

    // Sanitised, not trusted. The greeting argument is checked only for being
    // non-empty and ASCII, and `strip_terminator` removes just the *trailing*
    // CR — so `EHLO a\rb` yields a bare CR that lands in this header, is
    // written to the spool, and is relayed onward. A parser treating bare CR
    // as a line break sees a forged header.
    //
    // `Address::parse` was hardened against exactly this and the EHLO name,
    // which reaches the same header, was left unguarded. Parentheses, angle
    // brackets and semicolons are structural here too.
    let helo = sanitise_for_header(session.peer_name().unwrap_or("unknown"));
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

/// The shared form of [`crate::session::ReturnPathCheck`].
///
/// Named so the type is not repeated at every call site, and shared rather than
/// cloned per connection: it holds the SRS key ring, and a copy per concurrent
/// session would be a copy of the key material per session.
pub type SharedReturnPathCheck = dyn Fn(&str) -> Result<(), usize> + Send + Sync;

#[derive(Clone)]
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
    /// Connections served at once **from one address**.
    ///
    /// The global cap alone is a denial-of-service waiting to happen: one host
    /// opening 256 connections and holding them takes the server away from
    /// everyone else, and it does not have to send a single byte to do it.
    ///
    /// Refused rather than queued, unlike the global cap. A queue would let one
    /// address occupy the accept path indefinitely, and a peer that is already
    /// running several conversations here is being asked to use them rather
    /// than being turned away for good — which is why the refusal is `421`.
    ///
    /// Generous enough for a legitimate sender with a burst: providers open
    /// several connections in parallel to the same MX routinely.
    pub max_per_address: usize,
    /// Longest a single connection may live, however busy it is.
    ///
    /// The per-command timeout resets on every command, so a client sending
    /// `NOOP` every few minutes holds its slot indefinitely. With a connection
    /// cap in place, enough such clients close the server to everyone else —
    /// the cap becomes the means of denial rather than the defence against it.
    pub max_session: Duration,
    /// The certificate this listener serves, or `None` for plaintext only.
    ///
    /// The presence of the configuration *is* the advertisement: `STARTTLS`
    /// appears in the `EHLO` response exactly when there is something to
    /// upgrade to. The previous shape — a `bool` beside no implementation —
    /// could say "advertise it" while the server answered `220 Ready` and kept
    /// reading plaintext, which is a downgrade that looks like a working
    /// encrypted session from the outside. That state is now unrepresentable.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// Refuse recipients whose sender cannot be given a return path (R-4).
    ///
    /// Shared rather than cloned per connection: it holds the SRS key ring,
    /// and one copy per concurrent session would be one copy of the key
    /// material per session.
    ///
    /// `None` means no sender is refused for this reason, which is what a
    /// Pigeon with no forwarding configured should do — and what keeps the
    /// protocol tests independent of the rewriting scheme.
    pub return_path: Option<Arc<SharedReturnPathCheck>>,
}

impl std::fmt::Debug for ServerConfig {
    /// Hand-written because the return-path check is a closure. It shows
    /// whether one is wired in, which is the operationally interesting bit.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("hostname", &self.hostname)
            .field("max_message_size", &self.max_message_size)
            .field("command_timeout", &self.command_timeout)
            .field("data_timeout", &self.data_timeout)
            .field("max_connections", &self.max_connections)
            .field("max_per_address", &self.max_per_address)
            .field("max_session", &self.max_session)
            .field("tls", &self.tls.is_some())
            .field("return_path", &self.return_path.is_some())
            .finish()
    }
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
            max_per_address: 20,
            max_session: Duration::from_secs(3600),
            tls: None,
            return_path: None,
        }
    }
}

/// Serve until the process ends.
pub async fn serve<S: MessageSink>(
    listener: TcpListener,
    config: ServerConfig,
    sink: S,
) -> io::Result<()> {
    serve_with_shutdown(
        listener,
        config,
        sink,
        std::future::pending(),
        Duration::ZERO,
    )
    .await
}

/// Serve until `shutdown` resolves, then drain.
///
/// The order is the whole design. **Stop accepting first**: a drain that runs
/// while new connections are still arriving does not converge, and the process
/// would be held open by exactly the traffic it is trying to stop taking. Then
/// wait, up to `drain`, for the conversations already in progress — a session
/// that is mid-`DATA` is one whose sender is waiting to be told whether Pigeon
/// took the message, and cutting it produces a retry that could have been
/// avoided by waiting a few seconds.
///
/// What happens at the bound is deliberate too: connections still open are
/// dropped. Nothing is lost by that, because acceptance is durable exactly when
/// the queue transaction commits — a session cut before its `250` never had one,
/// and its sender retries.
pub async fn serve_with_shutdown<S: MessageSink>(
    listener: TcpListener,
    config: ServerConfig,
    sink: S,
    shutdown: impl Future<Output = ()>,
    drain: Duration,
) -> io::Result<()> {
    let config = Arc::new(config);
    let max = config.max_connections;
    let limit = Arc::new(Semaphore::new(max));
    let addresses = PerAddress::default();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };

        let (stream, peer) = match accepted {
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

        // Per address, and taken *after* the global permit so the two caps
        // compose rather than racing: a refusal here releases the global permit
        // immediately by dropping it at the end of the block.
        let Some(per_address) = addresses.take(peer.ip(), config.max_per_address) else {
            tracing::debug!(%peer, "refusing a connection: too many from this address");
            let mut stream = Stream::Plain(stream);
            let _ = write_reply(&mut stream, &reply::too_many_connections()).await;
            let _ = stream.shutdown().await;
            continue;
        };

        let config = Arc::clone(&config);
        let sink = sink.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let _per_address = per_address;
            if let Err(e) = handle(stream, peer, config, sink).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }

    // Closed before draining, not after: while it is open, a client can still
    // connect and be answered, and the drain would be waiting on work that is
    // still arriving.
    drop(listener);

    // Every permit back means every connection has finished. Acquiring them all
    // is the drain: there is no separate counter to keep in step with the one
    // the connection cap already maintains.
    let done = tokio::time::timeout(drain, limit.acquire_many(max as u32));
    match done.await {
        Ok(_) => tracing::info!("all connections closed"),
        Err(_) => {
            let still_open = max - limit.available_permits();
            tracing::warn!(
                still_open,
                "shutting down with connections still open; \
                 anything not yet acknowledged will be retried by its sender"
            );
        }
    }

    Ok(())
}

/// How many connections each address currently has.
///
/// A map rather than a semaphore per address, because addresses come and go:
/// what has to be bounded is the count, and an entry that reaches zero is
/// removed so a scan of the internet cannot make this grow without limit.
#[derive(Clone, Default)]
struct PerAddress(Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>);

impl PerAddress {
    /// Claim a slot for `address`, or `None` if it already has `max`.
    ///
    /// The returned guard is the whole point: a counter incremented here and
    /// decremented "somewhere in the handler" leaks on every early return, and
    /// the handler has several.
    fn take(&self, address: std::net::IpAddr, max: usize) -> Option<AddressSlot> {
        let mut map = match self.0.lock() {
            Ok(m) => m,
            // A poisoned lock means a handler panicked while holding it. The
            // count is unreliable either way, and refusing to proceed would
            // turn one panic into a listener that answers nobody.
            Err(e) => e.into_inner(),
        };

        let n = map.entry(address).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(AddressSlot {
            addresses: self.clone(),
            address,
        })
    }
}

/// Releases one address's slot when the connection ends, however it ends.
struct AddressSlot {
    addresses: PerAddress,
    address: std::net::IpAddr,
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut map = match self.addresses.0.lock() {
            Ok(m) => m,
            Err(e) => e.into_inner(),
        };
        if let Some(n) = map.get_mut(&self.address) {
            *n -= 1;
            // Removed at zero, so an address that has finished with this server
            // stops costing it memory.
            if *n == 0 {
                map.remove(&self.address);
            }
        }
    }
}

/// The connection, before and after a `STARTTLS` upgrade.
///
/// An enum rather than a generic parameter, because the upgrade happens *to* a
/// live connection: the same session, the same peer, the same loop. A generic
/// would need the whole handler instantiated twice and the plaintext half to
/// hand control to the encrypted half, which is a second copy of the
/// conversation and a second place for the state rules to be got wrong.
enum Stream {
    Plain(TcpStream),
    // Boxed: `TlsStream` is large, and an enum is as big as its largest
    // variant — every connection would carry that footprint whether or not it
    // ever negotiates TLS.
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl Stream {
    /// Perform the server side of the handshake, consuming the plaintext
    /// connection.
    ///
    /// A failed handshake ends the connection. It is never retried in
    /// plaintext: the client asked for TLS and was told `220`, so anything it
    /// sends next it believes to be encrypted.
    async fn upgrade(self, config: Arc<rustls::ServerConfig>) -> io::Result<Self> {
        match self {
            Self::Plain(tcp) => match tokio_rustls::TlsAcceptor::from(config).accept(tcp).await {
                Ok(tls) => Ok(Self::Tls(Box::new(tls))),
                Err(e) => Err(e),
            },
            // The session refuses a second `STARTTLS` with 503, so this cannot
            // be reached from the protocol.
            Self::Tls(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "STARTTLS on a connection that is already encrypted",
            )),
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.shutdown().await,
            Self::Tls(s) => s.shutdown().await,
        }
    }
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Whether the connection loop should keep going.
enum Flow {
    Continue,
    Stop,
}

/// Drive one connection.
async fn handle<S: MessageSink>(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    sink: S,
) -> io::Result<()> {
    let mut stream = Stream::Plain(stream);
    let mut session = Session::new(
        config.hostname.clone(),
        config.tls.is_some(),
        config.max_message_size,
    );
    if let Some(check) = config.return_path.clone() {
        session = session.with_return_path_check(Box::new(move |sender| check(sender)));
    }
    let mut lines = LineReader::new(MAX_COMMAND_LINE);
    let mut line = Vec::with_capacity(MAX_COMMAND_LINE);
    let mut chunk = vec![0u8; 8 * 1024];
    let mut data: Option<DataReader> = None;
    // Pinned at `MAIL FROM`, taken at delivery, dropped by `RSET` and by the
    // end of every transaction. `None` outside one.
    let mut transaction: Option<S::Transaction> = None;
    let started = Instant::now();

    tracing::debug!(%peer, "connection opened");

    // Before the banner. A peer refused here is told once and hung up on; a
    // peer refused later has already been given a conversation to spend.
    if let Connection::Refuse(reason) = sink.accepts_connection(peer).await {
        tracing::info!(%peer, %reason, "refusing a connection");
        let _ = write_reply(&mut stream, &reply::service_refused(&reason)).await;
        let _ = stream.shutdown().await;
        return Ok(());
    }

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

        let phase = if data.is_some() {
            config.data_timeout
        } else {
            config.command_timeout
        };
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
            if let Flow::Stop = finish_data(
                transaction.take(),
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
        }

        lines.feed(input);

        loop {
            match lines.take_line(&mut line) {
                Ok(true) => {
                    match step(
                        &mut transaction,
                        &mut stream,
                        &mut session,
                        &sink,
                        peer,
                        &line,
                    )
                    .await?
                    {
                        Step::Continue => {}
                        Step::Close => return Ok(()),
                        Step::StartTls(reply) => {
                            let Some(tls) = config.tls.clone() else {
                                // The session only answers `StartTls` when it
                                // was told TLS is available, which is exactly
                                // `config.tls.is_some()`.
                                tracing::error!(%peer, "STARTTLS agreed with no TLS configured");
                                return Ok(());
                            };

                            write_reply(&mut stream, &reply).await?;

                            // Everything buffered is discarded *before* the
                            // handshake, and nothing read in plaintext is
                            // carried across it. A client that pipelines
                            // `STARTTLS\r\nMAIL FROM:<...>` in one packet has
                            // put that second command in this buffer, and
                            // executing it after the upgrade would let an
                            // attacker who can inject plaintext have their
                            // commands attributed to the encrypted session —
                            // the injection half of CVE-2011-0411.
                            //
                            // `line` is cleared too: `take_line` leaves the
                            // command that was just parsed in it.
                            lines.discard();
                            line.clear();
                            // Neither can be set here — the session refuses
                            // STARTTLS inside a transaction — but the rule is
                            // "nothing survives", and stating it once is
                            // cheaper than re-deriving it whenever the state
                            // machine changes.
                            data = None;
                            transaction = None;

                            stream = match stream.upgrade(tls).await {
                                Ok(s) => s,
                                Err(e) => {
                                    // No plaintext fallback. The client was
                                    // told `220` and believes everything it
                                    // sends next is encrypted.
                                    tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                    return Ok(());
                                }
                            };

                            // A fresh EHLO is required: the session forgets the
                            // client's greeting and its envelope, because
                            // anything learned before the handshake was learned
                            // from an unauthenticated conversation.
                            session.tls_established();
                            tracing::debug!(%peer, "TLS established");
                            break;
                        }
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
                                    transaction.take(),
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
    /// The client asked for TLS and the session agreed. The reply is not sent
    /// here: the connection loop sends it, clears what it has buffered, and
    /// performs the handshake.
    StartTls(Reply),
}

/// Handle one framed command line.
async fn step<S: MessageSink>(
    transaction: &mut Option<S::Transaction>,
    stream: &mut Stream,
    session: &mut Session,
    sink: &S,
    peer: SocketAddr,
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
    // Consult routing only for a RCPT that is both in sequence and
    // syntactically valid. Skipping either check answers 550 "no such user"
    // when the real fault is 503 "bad sequence" or 501 "syntax error", which
    // sends the operator hunting a routing problem that does not exist.
    //
    // The refusal goes through the session rather than straight to the socket,
    // so it counts against the error budget: otherwise probing an address list
    // costs an attacker nothing and a directory harvest runs until the session
    // lifetime expires.
    if let command::Command::Rcpt { path, .. } = cmd
        && matches!(session.state(), State::Mail | State::Rcpt)
        && pigeon_types::Address::parse(path).is_ok()
    {
        let decision = match transaction.as_mut() {
            Some(txn) => {
                sink.accepts_recipient(txn, path, &session.envelope().recipients)
                    .await
            }
            // No transaction means no `MAIL FROM`, which the sequence check
            // above has already excluded.
            None => Recipient::Reject,
        };

        match decision {
            Recipient::Accept => {}
            Recipient::Reject => {
                tracing::debug!(recipient = %path, "recipient refused");
                let action = session.recipient_refused();
                return match emit(stream, action).await? {
                    Flow::Continue => Ok(Step::Continue),
                    Flow::Stop => Ok(Step::Close),
                };
            }
            Recipient::Defer => {
                // Not counted against the error budget: the address is not the
                // problem and the sender is being told to send it separately,
                // which is cooperation rather than probing.
                tracing::debug!(recipient = %path, "recipient deferred to another transaction");
                return match emit(stream, Action::Reply(reply::recipient_deferred())).await? {
                    Flow::Continue => Ok(Step::Continue),
                    Flow::Stop => Ok(Step::Close),
                };
            }
        }
    }

    // `MAIL FROM` opens a transaction and `RSET` — or any other reset of the
    // state — closes it. Pinned *after* the command is accepted, so a refused
    // `MAIL FROM` does not pin anything.
    let starts_transaction = matches!(cmd, command::Command::Mail { .. });
    let action = session.advance(cmd);
    let begins_data = matches!(action, Action::ReadData(_));

    // Handed back rather than written here. The upgrade belongs to the
    // connection loop, which owns the buffers that must not survive it.
    if let Action::StartTls(reply) = action {
        return Ok(Step::StartTls(reply));
    }

    match session.state() {
        State::Mail if starts_transaction => {
            *transaction = Some(sink.begin(peer, &session.envelope().sender))
        }
        State::Mail | State::Rcpt | State::Data => {}
        // Anything else means there is no transaction in progress: `RSET`,
        // a fresh `EHLO`, or a closed session.
        _ => *transaction = None,
    }

    match emit(stream, action).await? {
        Flow::Stop => Ok(Step::Close),
        Flow::Continue if begins_data => Ok(Step::BeginData),
        Flow::Continue => Ok(Step::Continue),
    }
}

/// Hand a finished body to the sink and answer the client.
async fn finish_data<S: MessageSink>(
    transaction: Option<S::Transaction>,
    stream: &mut Stream,
    session: &mut Session,
    sink: &S,
    config: &ServerConfig,
    peer: SocketAddr,
    reader: DataReader,
) -> io::Result<Flow> {
    let envelope = session.envelope().clone();
    let received = received_header(&config.hostname, session, peer, session.is_tls());
    let too_large = reader.is_too_large();
    let malformed = reader.contains_nul();
    let body = reader.into_body();

    // The trace stack is the only loop guard that reaches beyond systems
    // Pigeon can see. Refusing permanently is deliberate: a looping message
    // will loop again on retry, and each pass costs another delivery.
    let hops = count_hops(&body);
    let outcome = if malformed {
        // Before the size check: "this cannot be relayed at all" is a more
        // useful answer than "send a smaller one", and the sender learns it
        // while the message is still theirs to report on.
        tracing::warn!(%peer, "refusing message: the body contains a NUL octet");
        Err(DataError::Malformed)
    } else if too_large {
        Err(DataError::TooLarge)
    } else if hops >= MAX_HOPS {
        tracing::warn!(%peer, hops, "refusing message: too many trace hops, likely a loop");
        Err(DataError::TooManyHops)
    } else {
        let Some(transaction) = transaction else {
            // No pinned transaction means no `MAIL FROM`, which the session
            // state machine has already refused — the body cannot be here.
            tracing::error!(%peer, "message body without a transaction");
            return Ok(Flow::Stop);
        };
        sink.deliver(
            transaction,
            Message {
                peer: peer.ip(),
                helo: session.peer_name().unwrap_or_default().to_string(),
                envelope,
                received,
                body,
            },
        )
        .await
    };

    let action = session.data_received(outcome);
    emit(stream, action).await
}

/// Write whatever an action asked for, and say whether to keep going.
async fn emit(stream: &mut Stream, action: Action) -> io::Result<Flow> {
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
            // Never written here. The upgrade is the connection loop's, because
            // only it can discard the buffers that must not survive the
            // handshake — see `Step::StartTls`. Writing `220 Ready` from here
            // and returning `Continue` would be the silent downgrade this
            // module used to warn about: the client would negotiate while the
            // server kept reading plaintext.
            let _ = r;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "STARTTLS must be handled by the connection loop",
            ))
        }
    }
}

/// Write a reply, bounded in time.
///
/// A client that pipelines commands and then stops reading will fill the
/// kernel send buffer and park `write_all` forever. Because the session
/// lifetime is only checked at the top of the read loop, control never returns
/// there — so an unbounded write defeats both the session cap and the
/// connection cap at once, and it is cheap to arrange: one 8 KB read of
/// pipelined `EHLO` produces roughly 100 KB of replies.
async fn write_reply(stream: &mut Stream, r: &Reply) -> io::Result<()> {
    let wire = r.to_wire();
    match tokio::time::timeout(WRITE_TIMEOUT, async {
        stream.write_all(wire.as_bytes()).await?;
        stream.flush().await
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "peer stopped reading",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_leading_trace_headers() {
        assert_eq!(count_hops(b"Subject: hi\r\n\r\nbody\r\n"), 0);
        assert_eq!(count_hops(b"Received: a\r\nSubject: hi\r\n\r\nbody\r\n"), 1);
        assert_eq!(count_hops(b"Received: a\r\nReceived: b\r\n\r\nbody\r\n"), 2);
        // Case-insensitive, as header names are.
        assert_eq!(count_hops(b"RECEIVED: a\r\nreceived: b\r\n\r\nx\r\n"), 2);
    }

    #[test]
    fn stops_counting_at_the_body() {
        // Otherwise a message quoting trace headers in its body could be made
        // to look like it is looping, and would be refused permanently.
        let msg = b"Received: real\r\n\r\nReceived: a\r\nReceived: b\r\nReceived: c\r\n";
        assert_eq!(count_hops(msg), 1);
    }

    #[test]
    fn tolerates_bare_lf_headers() {
        assert_eq!(count_hops(b"Received: a\nReceived: b\n\nbody\n"), 2);
    }

    #[test]
    fn sanitises_peer_supplied_header_text() {
        // A bare CR survives command framing, and a header carrying one can be
        // read as two by a lenient downstream parser.
        assert_eq!(sanitise_for_header("a\rb"), "a?b");
        assert_eq!(sanitise_for_header("a\nb"), "a?b");
        // Structural characters in the header's own syntax.
        assert_eq!(sanitise_for_header("evil(comment)"), "evil?comment?");
        assert_eq!(sanitise_for_header("a;b<c>d"), "a?b?c?d");
        // Ordinary names pass through untouched.
        assert_eq!(sanitise_for_header("mail.example.com"), "mail.example.com");
    }

    #[test]
    fn truncates_overlong_header_text() {
        // The greeting can be most of a command line; a trace header is not the
        // place for hundreds of bytes of attacker-chosen text.
        let long = "a".repeat(500);
        let out = sanitise_for_header(&long);
        assert!(out.len() < 200, "not truncated: {} bytes", out.len());
        assert!(out.ends_with("..."));
    }

    #[test]
    fn ignores_continuation_lines() {
        // A folded header continues with whitespace and is not a new hop.
        let msg = b"Received: from a\r\n\tby b\r\n\tfor <c>\r\nReceived: second\r\n\r\nx";
        assert_eq!(count_hops(msg), 2);
    }
}
