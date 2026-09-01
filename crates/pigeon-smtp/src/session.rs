//! The SMTP receiver state machine.
//!
//! Pure state transitions: commands in, actions out, no I/O. That makes the
//! protocol testable without sockets, which matters because the properties that
//! most need testing — sequencing, limits, and what survives STARTTLS — are the
//! ones hardest to observe from outside.

use pigeon_types::Address;

use crate::command::{Command, ParseError};
use crate::reply::{self, Reply};

/// Recipients accepted in one transaction before further ones are refused.
pub const MAX_RECIPIENTS: usize = 100;

/// Consecutive protocol errors tolerated before the connection is dropped.
///
/// A client sending nothing but garbage is either broken or probing. Neither
/// deserves an unbounded number of round trips.
///
/// Consecutive, not cumulative: a connection held open for hours will collect
/// occasional errors between perfectly good traffic, and dropping it for that
/// punishes exactly the well-behaved senders worth keeping.
pub const MAX_ERRORS: usize = 10;

/// Refused recipients tolerated over the whole connection.
///
/// Deliberately cumulative rather than consecutive, unlike [`MAX_ERRORS`].
/// Probing an address list produces a refusal followed by something that
/// succeeds, so a counter that resets on success is never reached — the
/// harvest simply continues until the session lifetime runs out.
///
/// Set well above what ordinary mail produces: a legitimate sender occasionally
/// has a stale address, but does not walk a dictionary.
pub const MAX_REFUSALS: usize = 20;

/// Commands accepted over one connection, of any kind.
///
/// The error budget catches a client sending garbage and the refusal budget
/// catches one walking an address list. Neither catches a client sending
/// *valid* commands for ever: `RSET`, `NOOP` and `EHLO` all reset or never
/// touch those counters, so a connection can be kept busy indefinitely at no
/// cost to the sender. The session lifetime bounds the wall clock; this bounds
/// the work.
///
/// Generous, because pipelining a hundred recipients is a hundred commands and
/// a mailing list relay does that legitimately.
pub const MAX_COMMANDS: usize = 2_000;

/// Failed authentication attempts tolerated on one connection.
///
/// Small on purpose, and separate from the error budget. A client that gets its
/// own password wrong three times will not get it right on the twentieth, and
/// every attempt costs this server an Argon2 verification while costing the
/// client one line — which is the asymmetry an attacker would spend.
pub const MAX_AUTH_FAILURES: usize = 3;

/// How authentication is going.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Auth {
    /// Never attempted, or attempted and failed.
    None,
    /// A `334` was sent and the next line is the client's response.
    ///
    /// The mechanism is carried because `LOGIN` needs two exchanges and
    /// `PLAIN` one, and the reply to send next depends on which.
    Awaiting(Pending),
    /// Authenticated as this principal.
    As(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    /// `AUTH PLAIN` with no initial response: one line, `authzid\0authcid\0pass`.
    Plain,
    /// `AUTH LOGIN`, waiting for the username.
    LoginUsername,
    /// `AUTH LOGIN`, waiting for the password. Carries the username already
    /// given.
    LoginPassword(String),
}

/// Where a session is in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Connected, no greeting yet.
    Greeting,
    /// Greeted, no transaction in progress.
    Ready,
    /// `MAIL FROM` accepted.
    Mail,
    /// At least one `RCPT TO` accepted.
    Rcpt,
    /// Body is being received.
    Data,
    /// Session is finished.
    Closed,
}

/// What the I/O layer should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this reply and continue reading commands.
    Reply(Reply),
    /// Send this reply, then read the message body until the end-of-data marker.
    ReadData(Reply),
    /// Send this reply, then negotiate TLS.
    StartTls(Reply),
    /// Send this reply, then close the connection.
    Close(Reply),
    /// Check these credentials, then tell the session the answer.
    ///
    /// The session does not verify anything itself: credentials live in the
    /// database, checking one costs an Argon2 verification, and neither belongs
    /// in a state machine that is meant to be synchronous and pure. What it
    /// owns is *when* authentication may be attempted and what a failure costs.
    Authenticate { username: String, password: String },
}

/// The envelope accumulated by a transaction.
///
/// Owned rather than borrowed: an envelope outlives the individual command
/// lines it was read from. That is a handful of small allocations per
/// transaction, not per byte — the zero-copy contract is about message bodies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Envelope {
    /// Empty for the null sender used by bounces.
    pub sender: String,
    pub recipients: Vec<String>,
}

impl Envelope {
    /// Whether this is a bounce, which may have no sender but must have a
    /// recipient.
    #[inline]
    pub fn is_bounce(&self) -> bool {
        self.sender.is_empty()
    }
}

/// A message the server accepted, ready to be handed on.
///
/// The trace header is carried beside the body rather than prepended into it.
/// Prepending would mean copying the whole message to make room at the front —
/// a cost proportional to the message, paid for a few hundred bytes of text.
/// Consumers write the two in sequence instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub envelope: Envelope,
    /// The client's address, and the name it gave in EHLO.
    ///
    /// Carried on the message because SPF is evaluated against the connecting
    /// IP, and the sink is where authentication happens. Recovering them by
    /// parsing the `Received:` header back would mean trusting a header this
    /// process just wrote for a fact it already had.
    pub peer: std::net::IpAddr,
    pub helo: String,
    /// The `Received:` header, already CRLF-terminated.
    pub received: String,
    /// The body exactly as it arrived, dot-unstuffed and otherwise untouched.
    pub body: Vec<u8>,
}

impl Message {
    /// The complete message, header then body.
    ///
    /// Allocates and copies, so prefer writing the two parts in sequence where
    /// the destination allows it. Provided for the cases that genuinely need
    /// one contiguous slice.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.received.len() + self.body.len());
        out.extend_from_slice(self.received.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// One SMTP conversation.
pub struct Session {
    state: State,
    hostname: String,
    peer_name: Option<String>,
    envelope: Envelope,
    tls: bool,
    tls_available: bool,
    max_message_size: usize,
    errors: usize,
    /// Every command seen on this connection, never reset. See
    /// [`MAX_COMMANDS`].
    commands: usize,
    /// Who the client is, if anyone.
    auth: Auth,
    /// Failed authentication attempts on this connection.
    ///
    /// Separate from the error budget and much smaller: a client that gets its
    /// own password wrong three times is not going to get it right on the
    /// twentieth, and every attempt costs this server an Argon2 verification —
    /// which is exactly the asymmetry an attacker would use.
    auth_failures: usize,
    /// Whether authentication is offered at all. Set by the listener: the
    /// submission port advertises it and port 25 does not.
    auth_available: bool,
    /// Whether a transaction may begin without it.
    ///
    /// The submission port requires it; port 25 must not, since mail from
    /// strangers is the entire job there. This is the single flag that
    /// separates a submission service from an open relay.
    auth_required: bool,
    /// Refused recipients, counted for the life of the connection.
    ///
    /// Separate from `errors`, which resets on success. A directory harvest is
    /// `RCPT`, `NOOP`, `RCPT`, `NOOP` — every refusal followed by something
    /// that succeeds — so a resettable counter never reaches its limit and the
    /// probing is bounded only by the session lifetime.
    refusals: usize,
    /// Whether a sender can be given a working return path, if anything has
    /// been wired in to answer.
    ///
    /// A boxed predicate rather than a dependency on `pigeon-auth`: this crate
    /// speaks the protocol, and the rewriting scheme is not its business. What
    /// it needs to know is one bit, at one point in the transaction.
    return_path: Option<ReturnPathCheck>,
}

impl std::fmt::Debug for Session {
    /// Hand-written because the return-path check is a closure.
    ///
    /// The envelope is deliberately included: it is what a session is *about*,
    /// and a `Debug` that hid it would be useless in exactly the case anyone
    /// formats a session — working out which transaction misbehaved.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("state", &self.state)
            .field("hostname", &self.hostname)
            .field("peer_name", &self.peer_name)
            .field("envelope", &self.envelope)
            .field("tls", &self.tls)
            .field("errors", &self.errors)
            .field("commands", &self.commands)
            .field("refusals", &self.refusals)
            .field("return_path", &self.return_path.is_some())
            .finish()
    }
}

/// Answers "can this sender be rewritten?" for [`Session`].
///
/// `Err` carries the octets the rewritten local part would have taken, for the
/// log — never for the reply, which is attacker-visible.
pub type ReturnPathCheck = Box<dyn Fn(&str) -> Result<(), usize> + Send + Sync>;

impl Session {
    /// Start a session. The caller sends the greeting returned by
    /// [`Session::greeting`].
    pub fn new(hostname: impl Into<String>, tls_available: bool, max_message_size: usize) -> Self {
        Self {
            state: State::Greeting,
            hostname: hostname.into(),
            peer_name: None,
            envelope: Envelope::default(),
            tls: false,
            tls_available,
            max_message_size,
            errors: 0,
            commands: 0,
            auth: Auth::None,
            auth_failures: 0,
            auth_available: false,
            auth_required: false,
            refusals: 0,
            return_path: None,
        }
    }

    /// Offer authentication on this session.
    ///
    /// The submission listener sets it; port 25 does not. Advertising `AUTH` on
    /// the public MX would invite clients to send credentials to a port where
    /// nothing can use them, and where the connection may not even be
    /// encrypted.
    pub fn with_auth(mut self) -> Self {
        self.auth_available = true;
        self
    }

    /// Refuse `MAIL FROM` until the client has authenticated.
    ///
    /// The submission port sets this. Without it, a listener that advertised
    /// `AUTH` and accepted mail anyway would be an open relay with a login
    /// screen — the credential would be decoration.
    pub fn with_required_auth(mut self) -> Self {
        self.auth_available = true;
        self.auth_required = true;
        self
    }

    /// Who the client authenticated as, if anyone.
    pub fn principal(&self) -> Option<&str> {
        match &self.auth {
            Auth::As(name) => Some(name),
            _ => None,
        }
    }

    /// Whether the next line is a response to an authentication challenge
    /// rather than a command.
    ///
    /// The I/O layer has to ask, because a base64 blob is not a command and the
    /// parser is right to refuse it: `YWxpY2U=` is a syntax error everywhere
    /// except here.
    pub fn awaiting_auth(&self) -> bool {
        matches!(self.auth, Auth::Awaiting(_))
    }

    /// Consume a line that answers a `334`.
    pub fn auth_line(&mut self, line: &str) -> Action {
        let Auth::Awaiting(pending) = self.auth.clone() else {
            // Only reachable if a caller stopped asking `awaiting_auth` first.
            return self.protocol_error(reply::bad_sequence());
        };
        self.commands += 1;
        self.auth_response(pending, line.trim())
    }

    /// Record the outcome of an [`Action::Authenticate`].
    ///
    /// Called by the I/O layer once the credentials have been checked. A
    /// failure counts against a budget of its own and resets the state, so the
    /// next `AUTH` starts from the beginning rather than continuing a
    /// half-finished exchange.
    pub fn authenticated(&mut self, principal: Option<String>) -> Action {
        match principal {
            Some(name) => {
                self.auth = Auth::As(name);
                // Everything learned before authentication is kept: unlike
                // STARTTLS, `AUTH` does not change who the peer is talking to
                // or what they have already said in the clear. RFC 4954 §4
                // requires the *transaction* to be discarded, which the state
                // machine has anyway since `AUTH` is only accepted outside one.
                Action::Reply(reply::authenticated())
            }
            None => {
                self.auth = Auth::None;
                self.auth_failures += 1;
                if self.auth_failures >= MAX_AUTH_FAILURES {
                    self.state = State::Closed;
                    return Action::Close(reply::too_many_auth_failures());
                }
                Action::Reply(reply::authentication_failed())
            }
        }
    }

    /// Refuse recipients whose forwarding would need a return path that cannot
    /// be built (R-4).
    ///
    /// Wired in by the daemon, which owns the rewriting scheme. Left unset, no
    /// sender is refused for this reason — which is what the protocol tests
    /// want, and what a Pigeon with no forwarding configured should do.
    pub fn with_return_path_check(mut self, check: ReturnPathCheck) -> Self {
        self.return_path = Some(check);
        self
    }

    /// The banner to send on connect.
    pub fn greeting(&self) -> Reply {
        reply::service_ready(&self.hostname)
    }

    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    #[inline]
    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// The name the client gave in EHLO/HELO, if it has greeted.
    #[inline]
    pub fn peer_name(&self) -> Option<&str> {
        self.peer_name.as_deref()
    }

    /// The envelope of the transaction in progress.
    #[inline]
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Handle a line that failed to parse.
    pub fn advance_parse_error(&mut self, err: ParseError) -> Action {
        // A line that does not parse is still a command's worth of work, and a
        // cap that ignored them would be lifted by sending garbage instead.
        self.commands += 1;
        if self.commands > MAX_COMMANDS {
            self.state = State::Closed;
            return Action::Close(reply::too_many_commands());
        }

        self.errors += 1;
        if self.errors >= MAX_ERRORS {
            self.state = State::Closed;
            return Action::Close(reply::too_many_errors());
        }
        Action::Reply(match err {
            ParseError::TooLong => reply::line_too_long(),
            ParseError::UnknownCommand | ParseError::Empty => reply::command_unrecognised(),
            _ => reply::syntax_error(),
        })
    }

    /// Handle a parsed command.
    pub fn advance(&mut self, cmd: Command<'_>) -> Action {
        // Counted before anything else, including the sequence check: a client
        // that only ever sends commands out of sequence is still spending this
        // server's time, and the point of the cap is the work rather than the
        // correctness of what was asked for.
        self.commands += 1;
        if self.commands > MAX_COMMANDS {
            self.state = State::Closed;
            return Action::Close(reply::too_many_commands());
        }

        if self.state == State::Greeting && !cmd.allowed_before_greeting() {
            return self.protocol_error(reply::bad_sequence());
        }

        let action = match cmd {
            Command::Ehlo(name) => self.greet(name, true),
            Command::Helo(name) => self.greet(name, false),
            Command::Mail { path, params } => self.mail(path, params),
            Command::Rcpt { path, .. } => self.rcpt(path),
            Command::Data => self.data(),
            Command::Rset => {
                self.reset_transaction();
                Action::Reply(reply::ok())
            }
            Command::Noop => Action::Reply(reply::ok()),
            Command::Quit => {
                self.state = State::Closed;
                Action::Close(reply::bye(&self.hostname))
            }
            Command::StartTls => self.start_tls(),
            Command::Auth { mechanism, initial } => self.auth(mechanism, initial),
        };

        // Any command the server accepted clears the error run. The limit is
        // there to shed clients that only produce garbage, not to accumulate
        // grudges against clients that mostly work.
        if !matches!(&action, Action::Reply(r) | Action::Close(r) if r.is_error()) {
            self.errors = 0;
        }

        action
    }

    /// Called by the I/O layer once TLS negotiation has succeeded.
    ///
    /// Everything learned before the handshake is discarded, including the
    /// client's greeting. An attacker able to inject plaintext before STARTTLS
    /// could otherwise have that buffered input treated as though it arrived
    /// inside the encrypted session.
    pub fn tls_established(&mut self) {
        self.tls = true;
        self.peer_name = None;
        self.envelope = Envelope::default();
        self.state = State::Greeting;
    }

    /// Called by the I/O layer once a body has been received.
    ///
    /// The transaction is cleared either way, so a failed message cannot leak
    /// recipients into the next one.
    pub fn data_received(&mut self, outcome: Result<String, DataError>) -> Action {
        self.reset_transaction();
        Action::Reply(match outcome {
            Ok(id) => reply::queued(&id),
            Err(DataError::TooLarge) => reply::message_too_large(),
            Err(DataError::Malformed) => reply::message_malformed(),
            Err(DataError::Rejected) => reply::message_rejected(),
            Err(DataError::TooManyHops) => reply::too_many_hops(),
            Err(DataError::Temporary) => reply::temporary_failure(),
        })
    }

    fn greet(&mut self, name: &str, extended: bool) -> Action {
        // A greeting resets any transaction in progress.
        self.reset_transaction();
        self.peer_name = Some(name.to_owned());
        self.state = State::Ready;

        if !extended {
            return Action::Reply(reply::ok());
        }

        // SMTPUTF8 is deliberately absent: the command parser refuses non-ASCII,
        // so advertising it would invite senders to use internationalised
        // addresses and then refuse them. An advertisement is a promise.
        let mut ext: Vec<std::borrow::Cow<'static, str>> = vec![
            std::borrow::Cow::Borrowed("8BITMIME"),
            std::borrow::Cow::Borrowed("PIPELINING"),
            // Lets a sender skip transmitting a message that will be refused.
            std::borrow::Cow::Owned(format!("SIZE {}", self.max_message_size)),
        ];
        // Only when it can actually be used: advertising `AUTH` before TLS
        // would invite a client to send credentials in the clear, and a client
        // that does so has already given them away whatever the server does
        // next.
        if self.auth_available && self.tls {
            ext.push(std::borrow::Cow::Borrowed("AUTH PLAIN LOGIN"));
        }

        // Advertising STARTTLS once TLS is active would invite a client to
        // negotiate twice.
        if self.tls_available && !self.tls {
            ext.push(std::borrow::Cow::Borrowed("STARTTLS"));
        }
        Action::Reply(reply::ehlo_ok_owned(&self.hostname, ext))
    }

    fn mail(&mut self, path: &str, params: &str) -> Action {
        // Before anything about the address: an unauthenticated transaction on
        // the submission port is the open-relay case, and it is refused here
        // rather than at `RCPT` so nothing is recorded about it at all.
        if self.auth_required && !matches!(self.auth, Auth::As(_)) {
            return self.protocol_error(reply::authentication_required());
        }

        if self.state != State::Ready {
            return self.protocol_error(reply::bad_sequence());
        }
        // The null sender is valid and is not an address, so it skips parsing.
        if !path.is_empty() && Address::parse(path).is_err() {
            return self.protocol_error(reply::syntax_error());
        }

        // Honour the declared size. Advertising SIZE and then ignoring the
        // parameter makes the advertisement a lie: the sender is told it can
        // check in advance, transmits the whole body on that basis, and is
        // refused at the end anyway — having occupied memory for the duration.
        if let Some(declared) = declared_size(params)
            && declared > self.max_message_size
        {
            return self.protocol_error(reply::message_too_large());
        }

        self.envelope.sender = path.to_owned();
        self.state = State::Mail;
        Action::Reply(reply::ok())
    }

    fn rcpt(&mut self, path: &str) -> Action {
        if !matches!(self.state, State::Mail | State::Rcpt) {
            return self.protocol_error(reply::bad_sequence());
        }
        // Parsed here so that malformed addresses are refused at the door
        // rather than travelling into routing as though they were recipients.
        let Ok(parsed) = Address::parse(path) else {
            return self.protocol_error(reply::syntax_error());
        };

        // Before anything is recorded: a sender that cannot be given a return
        // path cannot be forwarded, and this is the last moment at which
        // refusing is still the upstream MTA's problem rather than Pigeon's
        // (R-4). Checked here rather than at `MAIL FROM` because it is only a
        // problem for a recipient that would actually be forwarded.
        //
        // The null sender is exempt: a bounce is not forwarded and needs no
        // return path of its own.
        if !self.envelope.sender.is_empty()
            && let Some(check) = &self.return_path
            && let Err(octets) = check(&self.envelope.sender)
        {
            tracing::info!(
                octets,
                "refusing a recipient: the rewritten sender would not fit in a local part"
            );
            return Action::Reply(reply::sender_cannot_be_rewritten());
        }

        // A repeat is accepted, as the specification requires, but recorded
        // once. Without this, a hundred identical RCPT commands produce a
        // hundred deliveries of one message to one mailbox, and consume the
        // recipient budget while doing it.
        //
        // The byte-identical case is checked first and without parsing, which
        // is both the common repeat and the cheap one. It deliberately runs
        // *before* the recipient cap: a client sitting at the limit that
        // resends an address already in the envelope has asked for nothing
        // new, and answering 452 would tell it to retry work already done.
        if self.envelope.recipients.iter().any(|r| r == path) {
            self.state = State::Rcpt;
            return Action::Reply(reply::ok());
        }

        // The cap next, so that the parsing pass below cannot be made to run
        // once per command by a client that is already at the limit. The cost
        // of that ordering is narrow: a repeat differing only in domain case,
        // arriving at the cap, is answered 452 rather than 250. The client
        // retries and loses nothing.
        if self.envelope.recipients.len() >= MAX_RECIPIENTS {
            // 4xx, not 5xx: the limit is ours, and the client may legitimately
            // retry with a smaller batch.
            return Action::Reply(reply::too_many_recipients());
        }

        // Comparison folds the domain only. Folding the local part as well
        // would merge `Bob@x` into `bob@x`, answer 250, and then silently drop
        // one of them — see `Address::same_mailbox`.
        let duplicate = self
            .envelope
            .recipients
            .iter()
            .any(|r| Address::parse(r).is_ok_and(|existing| existing.same_mailbox(&parsed)));

        if duplicate {
            self.state = State::Rcpt;
            return Action::Reply(reply::ok());
        }
        self.envelope.recipients.push(path.to_owned());
        self.state = State::Rcpt;
        Action::Reply(reply::ok())
    }

    /// Record that a recipient was refused by routing.
    ///
    /// Counted against the error budget so that walking an address list is not
    /// free. Without this, refusals cost an attacker nothing and a directory
    /// harvest is bounded only by the session lifetime.
    pub fn recipient_refused(&mut self) -> Action {
        self.refusals += 1;
        if self.refusals >= MAX_REFUSALS {
            self.state = State::Closed;
            return Action::Close(reply::too_many_errors());
        }
        Action::Reply(reply::no_such_user())
    }

    fn data(&mut self) -> Action {
        if self.state != State::Rcpt {
            return self.protocol_error(reply::bad_sequence());
        }
        self.state = State::Data;
        Action::ReadData(reply::start_mail_input())
    }

    /// `AUTH`, and the line that follows a `334`.
    ///
    /// Three refusals before any mechanism is considered, in this order:
    ///
    /// 1. **Not offered here.** Port 25 does not advertise it and does not
    ///    accept it. A relay that authenticated on the MX port would be a
    ///    second way in with no reason to exist.
    /// 2. **Not encrypted.** Credentials in the clear are credentials given
    ///    away; RFC 4954 §4 requires refusing, and `538` says why.
    /// 3. **Already authenticated, or inside a transaction.** Both are
    ///    sequence errors: re-authenticating mid-message would leave a message
    ///    whose sender was authorised by one principal and whose body arrived
    ///    under another.
    fn auth(&mut self, mechanism: &str, initial: Option<&str>) -> Action {
        if !self.auth_available {
            return self.protocol_error(reply::command_unrecognised());
        }
        if !self.tls {
            return self.protocol_error(reply::encryption_required());
        }
        if matches!(self.auth, Auth::As(_)) {
            return self.protocol_error(reply::already_authenticated());
        }
        if self.state != State::Ready && self.state != State::Greeting {
            return self.protocol_error(reply::bad_sequence());
        }

        // A line arriving while a challenge is outstanding is the response to
        // it, whatever it looks like: the mechanism decides what the bytes
        // mean, not the parser.
        if let Auth::Awaiting(pending) = self.auth.clone() {
            return self.auth_response(pending, mechanism);
        }

        match mechanism.to_ascii_uppercase().as_str() {
            "PLAIN" => match initial {
                Some(blob) => self.plain(blob),
                None => {
                    self.auth = Auth::Awaiting(Pending::Plain);
                    Action::Reply(reply::auth_challenge(""))
                }
            },
            "LOGIN" => match initial {
                // The username may ride along, which some clients do.
                Some(blob) => match decode_base64(blob) {
                    Some(username) => {
                        self.auth = Auth::Awaiting(Pending::LoginPassword(username));
                        Action::Reply(reply::auth_challenge("UGFzc3dvcmQ6"))
                    }
                    None => self.protocol_error(reply::auth_bad_encoding()),
                },
                None => {
                    self.auth = Auth::Awaiting(Pending::LoginUsername);
                    Action::Reply(reply::auth_challenge("VXNlcm5hbWU6"))
                }
            },
            // No CRAM-MD5 and no DIGEST-MD5: both need the password recoverable
            // on this side, which would mean storing something reversible
            // instead of an Argon2 hash. A weaker storage format is not worth a
            // mechanism whose only advantage is over a channel that must be
            // encrypted anyway.
            _ => self.protocol_error(reply::auth_mechanism_unsupported()),
        }
    }

    /// The client's answer to a `334`.
    fn auth_response(&mut self, pending: Pending, line: &str) -> Action {
        // `*` cancels, and is the client's right at any point (RFC 4954 §4).
        if line == "*" {
            self.auth = Auth::None;
            return Action::Reply(reply::auth_cancelled());
        }

        let Some(decoded) = decode_base64(line) else {
            self.auth = Auth::None;
            return self.protocol_error(reply::auth_bad_encoding());
        };

        match pending {
            Pending::Plain => self.plain_decoded(&decoded),
            Pending::LoginUsername => {
                self.auth = Auth::Awaiting(Pending::LoginPassword(decoded));
                Action::Reply(reply::auth_challenge("UGFzc3dvcmQ6"))
            }
            Pending::LoginPassword(username) => {
                self.auth = Auth::None;
                Action::Authenticate {
                    username,
                    password: decoded,
                }
            }
        }
    }

    fn plain(&mut self, blob: &str) -> Action {
        match decode_base64(blob) {
            Some(decoded) => self.plain_decoded(&decoded),
            None => {
                self.auth = Auth::None;
                self.protocol_error(reply::auth_bad_encoding())
            }
        }
    }

    /// `authzid\0authcid\0password`, of which the authorisation identity is
    /// ignored.
    ///
    /// Ignored rather than refused: clients send it empty or send the username
    /// again, and Pigeon has no notion of one principal acting as another. What
    /// authorises a sender address is the grant on the principal that
    /// authenticated, which is checked later and cannot be influenced from
    /// here.
    fn plain_decoded(&mut self, decoded: &str) -> Action {
        self.auth = Auth::None;
        let mut parts = decoded.split('\0');
        let (_authzid, username, password) = (parts.next(), parts.next(), parts.next());

        match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() => Action::Authenticate {
                username: u.to_string(),
                password: p.to_string(),
            },
            _ => self.protocol_error(reply::auth_bad_encoding()),
        }
    }

    fn start_tls(&mut self) -> Action {
        if !self.tls_available {
            return Action::Reply(reply::tls_not_available());
        }
        if self.tls {
            return self.protocol_error(reply::bad_sequence());
        }
        if !matches!(self.state, State::Greeting | State::Ready) {
            return self.protocol_error(reply::bad_sequence());
        }
        Action::StartTls(reply::tls_ready())
    }

    fn reset_transaction(&mut self) {
        self.envelope = Envelope::default();
        if self.state != State::Greeting && self.state != State::Closed {
            self.state = State::Ready;
        }
    }

    fn protocol_error(&mut self, r: Reply) -> Action {
        self.errors += 1;
        if self.errors >= MAX_ERRORS {
            self.state = State::Closed;
            return Action::Close(reply::too_many_errors());
        }
        Action::Reply(r)
    }
}

/// Decode a base64 line from a client.
///
/// Standard alphabet, padding required to be well formed but tolerated when
/// absent: clients differ, and a credential exchange is not the place to be
/// pedantic about a trailing `=`. Anything that is not base64 at all returns
/// `None`, which the caller turns into `501` — never into an empty password,
/// which would be a password nobody typed being checked against a hash.
fn decode_base64(input: &str) -> Option<String> {
    const INVALID: u8 = 0xff;
    let value = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => INVALID,
        }
    };

    let trimmed: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();

    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in trimmed {
        let v = value(byte);
        if v == INVALID {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    // Credentials are text. A blob that is valid base64 and not valid UTF-8 is
    // not a password anyone set through this project's own tooling.
    String::from_utf8(out).ok()
}

/// Read a `SIZE=` value from ESMTP parameters, if present and well formed.
fn declared_size(params: &str) -> Option<usize> {
    params.split_whitespace().find_map(|p| {
        // Parameter keywords are case-insensitive (RFC 1869 §4).
        let rest = (p.len() > 5 && p[..5].eq_ignore_ascii_case("SIZE=")).then(|| &p[5..])?;
        rest.parse().ok()
    })
}

/// Why a body could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataError {
    TooLarge,
    Temporary,
    /// The trace header stack suggests the message is going round in circles.
    TooManyHops,
    /// The body cannot be relayed as it stands: it carries an octet that makes
    /// one set of bytes two different messages. See [`crate::codec::DataStatus`].
    Malformed,
    /// Refused on content. Permanent, because the same bytes will be refused
    /// again — and said during the conversation, so the sender still has the
    /// message and reports the failure to whoever wrote it.
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::parse;

    fn session() -> Session {
        Session::new("mx1.example.net", true, 50 * 1024 * 1024)
    }

    // ------------------------------------------- the return-path refusal (R-4)

    /// Refuses any sender whose local part is longer than `limit`.
    fn refuse_longer_than(limit: usize) -> ReturnPathCheck {
        Box::new(move |sender: &str| {
            let local = sender.split('@').next().unwrap_or_default();
            if local.len() > limit {
                Err(local.len())
            } else {
                Ok(())
            }
        })
    }

    fn session_with_check(limit: usize) -> Session {
        let mut s = Session::new("mx1.example.net", false, 50 * 1024 * 1024)
            .with_return_path_check(refuse_longer_than(limit));
        run(&mut s, b"EHLO client.example");
        s
    }

    #[test]
    fn a_sender_that_cannot_be_rewritten_is_refused_at_rcpt() {
        // Before acceptance, so the upstream MTA still owns the message and
        // the DSN. After 250 there would be a message that can neither be
        // forwarded nor bounced.
        let mut s = session_with_check(5);
        run(&mut s, b"MAIL FROM:<averylongsenderaddress@sender.example>");

        let reply = run(&mut s, b"RCPT TO:<bob@example.com>");
        assert_eq!(code(&reply), 550, "{reply:?}");
        assert!(
            matches!(&reply, Action::Reply(r) if r.is_permanent()),
            "a retry would produce the same answer"
        );
        assert!(
            s.envelope().recipients.is_empty(),
            "a refused recipient was recorded anyway"
        );
    }

    #[test]
    fn a_sender_that_fits_is_accepted() {
        // The test above passes just as well if every recipient is refused.
        let mut s = session_with_check(5);
        run(&mut s, b"MAIL FROM:<short@sender.example>");
        assert_eq!(code(&run(&mut s, b"RCPT TO:<bob@example.com>")), 250);
        assert_eq!(s.envelope().recipients.len(), 1);
    }

    #[test]
    fn the_null_sender_is_never_refused() {
        // A bounce is not forwarded and needs no return path of its own, so
        // there is nothing to rewrite and nothing that can fail to fit.
        // Refusing here would reject every incoming DSN.
        //
        // The check refuses *everything*, so the exemption is the only thing
        // that can produce a 250. An earlier version used a length limit of
        // zero, which an empty sender passes — the test could not fail.
        let mut s = Session::new("mx1.example.net", false, 50 * 1024 * 1024)
            .with_return_path_check(Box::new(|sender: &str| Err(sender.len())));
        run(&mut s, b"EHLO client.example");
        run(&mut s, b"MAIL FROM:<>");
        assert_eq!(code(&run(&mut s, b"RCPT TO:<bob@example.com>")), 250);
    }

    #[test]
    fn without_a_check_no_sender_is_refused() {
        // The default. A Pigeon with nothing wired in refuses nobody for this
        // reason, which is what keeps the protocol tests independent of the
        // rewriting scheme.
        let mut s = session();
        run(&mut s, b"EHLO client.example");
        run(&mut s, b"MAIL FROM:<averylongsenderaddress@sender.example>");
        assert_eq!(code(&run(&mut s, b"RCPT TO:<bob@example.com>")), 250);
    }

    #[test]
    fn the_refusal_does_not_leak_the_limit_or_the_rewritten_form() {
        // Reply text is attacker-visible, and finding 21 is about what ends up
        // in it. The octet count goes to the log instead.
        let mut s = session_with_check(5);
        run(&mut s, b"MAIL FROM:<averylongsenderaddress@sender.example>");
        let reply = run(&mut s, b"RCPT TO:<bob@example.com>");
        let Action::Reply(reply) = reply else {
            panic!("expected a reply: {reply:?}")
        };
        let wire = reply.to_wire();
        assert!(!wire.contains("64"), "{wire}");
        assert!(!wire.contains("SRS"), "{wire}");
        assert!(!wire.contains("averylong"), "{wire}");
    }

    fn run(s: &mut Session, line: &[u8]) -> Action {
        // A challenge response is not a command, and the parser is right to
        // refuse it: the I/O layer asks the session which one it is.
        if s.awaiting_auth() {
            return s.auth_line(String::from_utf8_lossy(line).trim());
        }
        match parse(line) {
            Ok(cmd) => s.advance(cmd),
            Err(e) => s.advance_parse_error(e),
        }
    }

    fn code(a: &Action) -> u16 {
        match a {
            Action::Reply(r) | Action::ReadData(r) | Action::StartTls(r) | Action::Close(r) => {
                r.code
            }
            // Not a reply at all: the sink has to answer first. A test that
            // reaches here is asserting a code for a decision nobody has made.
            Action::Authenticate { .. } => panic!("authentication has no reply of its own"),
        }
    }

    #[test]
    fn happy_path() {
        let mut s = session();
        assert_eq!(s.greeting().code, 220);
        assert_eq!(code(&run(&mut s, b"EHLO client.example.org\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<a@example.org>\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<hello@example.net>\r\n")), 250);

        let action = run(&mut s, b"DATA\r\n");
        assert!(matches!(action, Action::ReadData(_)));
        assert_eq!(code(&action), 354);
        assert_eq!(s.state(), State::Data);

        let done = s.data_received(Ok("4bXk2m".into()));
        assert_eq!(code(&done), 250);
        assert_eq!(s.state(), State::Ready);
        // Transaction cleared, so recipients cannot leak into the next message.
        assert!(s.envelope().recipients.is_empty());
    }

    #[test]
    fn commands_before_greeting_are_refused() {
        let mut s = session();
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<a@b.com>\r\n")), 503);
        assert_eq!(code(&run(&mut s, b"DATA\r\n")), 503);
        // NOOP and QUIT remain available.
        assert_eq!(code(&run(&mut s, b"NOOP\r\n")), 250);
    }

    #[test]
    fn sequencing_is_enforced() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        // RCPT before MAIL.
        assert_eq!(code(&run(&mut s, b"RCPT TO:<a@b.com>\r\n")), 503);
        // DATA before any recipient.
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(code(&run(&mut s, b"DATA\r\n")), 503);
        // Second MAIL inside a transaction.
        run(&mut s, b"RCPT TO:<c@d.com>\r\n");
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<e@f.com>\r\n")), 503);
    }

    #[test]
    fn rset_clears_the_transaction() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        run(&mut s, b"RCPT TO:<c@d.com>\r\n");
        assert_eq!(code(&run(&mut s, b"RSET\r\n")), 250);
        assert_eq!(s.state(), State::Ready);
        assert!(s.envelope().recipients.is_empty());
        assert!(s.envelope().sender.is_empty());
    }

    #[test]
    fn greeting_again_resets_the_transaction() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        run(&mut s, b"RCPT TO:<c@d.com>\r\n");
        run(&mut s, b"EHLO c\r\n");
        assert_eq!(s.state(), State::Ready);
        assert!(s.envelope().recipients.is_empty());
    }

    #[test]
    fn null_sender_is_accepted_for_bounces() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<>\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<a@example.net>\r\n")), 250);
        assert!(s.envelope().is_bounce());
    }

    #[test]
    fn recipient_limit_is_temporary_not_permanent() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");

        // Distinct addresses: the limit counts recipients, and since repeats
        // are deduplicated they cannot be used to consume the budget.
        for i in 0..MAX_RECIPIENTS {
            let line = format!("RCPT TO:<x{i}@example.net>\r\n");
            assert_eq!(
                code(&run(&mut s, line.as_bytes())),
                250,
                "rejected recipient {i}"
            );
        }
        // 452 tells the client to retry with fewer, rather than to give up.
        assert_eq!(
            code(&run(&mut s, b"RCPT TO:<overflow@example.net>\r\n")),
            452
        );
        assert_eq!(s.envelope().recipients.len(), MAX_RECIPIENTS);

        // A repeat of one already accepted is still fine — it adds nothing.
        assert_eq!(code(&run(&mut s, b"RCPT TO:<x0@example.net>\r\n")), 250);
        assert_eq!(s.envelope().recipients.len(), MAX_RECIPIENTS);
    }

    // ----------------------------------------------------------- AUTH (M7)

    fn authenticating() -> Session {
        let mut s = Session::new("mx1.example.net", true, 1024).with_auth();
        // TLS first: `AUTH` is refused without it, which is most of the point.
        run(&mut s, b"EHLO client.test\r\n");
        run(&mut s, b"STARTTLS\r\n");
        s.tls_established();
        run(&mut s, b"EHLO client.test\r\n");
        s
    }

    #[test]
    fn auth_is_refused_in_the_clear() {
        // Credentials on an unencrypted connection are credentials given away,
        // whatever the server does next.
        let mut s = Session::new("mx1.example.net", true, 1024).with_auth();
        run(&mut s, b"EHLO client.test\r\n");
        assert_eq!(
            code(&run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")),
            538
        );
    }

    #[test]
    fn auth_is_not_offered_or_accepted_where_it_is_not_available() {
        // Port 25 does not advertise it and does not accept it: a relay that
        // authenticated on the MX port would be a second way in with no reason
        // to exist.
        let mut s = Session::new("mx1.example.net", true, 1024);
        run(&mut s, b"EHLO client.test\r\n");
        run(&mut s, b"STARTTLS\r\n");
        s.tls_established();
        let greeting = run(&mut s, b"EHLO client.test\r\n");
        let Action::Reply(r) = &greeting else {
            panic!("{greeting:?}")
        };
        assert!(!r.lines.iter().any(|l| l.contains("AUTH")), "{r:?}");
        assert_eq!(code(&run(&mut s, b"AUTH PLAIN AGEAYg==\r\n")), 500);
    }

    #[test]
    fn plain_carries_the_credentials_to_the_sink() {
        // The state machine decides *when*; the sink decides *whether*. Base64
        // of "\0alice\0secret".
        let mut s = authenticating();
        let action = run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
        assert_eq!(
            action,
            Action::Authenticate {
                username: "alice".into(),
                password: "secret".into()
            }
        );

        assert_eq!(code(&s.authenticated(Some("alice".into()))), 235);
        assert_eq!(s.principal(), Some("alice"));
    }

    #[test]
    fn plain_without_an_initial_response_takes_one_more_line() {
        let mut s = authenticating();
        assert_eq!(code(&run(&mut s, b"AUTH PLAIN\r\n")), 334);
        assert_eq!(
            run(&mut s, b"AGFsaWNlAHNlY3JldA==\r\n"),
            Action::Authenticate {
                username: "alice".into(),
                password: "secret".into()
            }
        );
    }

    #[test]
    fn login_is_two_challenges() {
        let mut s = authenticating();
        assert_eq!(code(&run(&mut s, b"AUTH LOGIN\r\n")), 334);
        // "alice"
        assert_eq!(code(&run(&mut s, b"YWxpY2U=\r\n")), 334);
        // "secret"
        assert_eq!(
            run(&mut s, b"c2VjcmV0\r\n"),
            Action::Authenticate {
                username: "alice".into(),
                password: "secret".into()
            }
        );
    }

    #[test]
    fn a_client_may_cancel() {
        let mut s = authenticating();
        run(&mut s, b"AUTH LOGIN\r\n");
        assert_eq!(code(&run(&mut s, b"*\r\n")), 501);
        // And the session is usable afterwards: cancelling is the client's
        // right, not an error to be punished for.
        assert_eq!(code(&run(&mut s, b"AUTH LOGIN\r\n")), 334);
    }

    #[test]
    fn malformed_credentials_are_refused_rather_than_decoded_to_nothing() {
        // A blob that is not base64 must not become an empty password checked
        // against a hash.
        let mut s = authenticating();
        assert_eq!(code(&run(&mut s, b"AUTH PLAIN not-base64!!\r\n")), 501);

        let mut s = authenticating();
        // Valid base64 with no NUL separators is not a PLAIN response.
        assert_eq!(code(&run(&mut s, b"AUTH PLAIN YWxpY2U=\r\n")), 501);
    }

    #[test]
    fn repeated_failures_end_the_connection() {
        // Every attempt costs this server an Argon2 verification and costs the
        // client one line. That asymmetry is the whole reason for the budget.
        let mut s = authenticating();
        for _ in 0..MAX_AUTH_FAILURES - 1 {
            run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
            assert_eq!(code(&s.authenticated(None)), 535);
        }
        run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
        let last = s.authenticated(None);
        assert_eq!(code(&last), 421);
        assert!(matches!(last, Action::Close(_)));
    }

    #[test]
    fn authenticating_twice_is_a_sequence_error() {
        // Re-authenticating mid-session would leave a message whose sender was
        // authorised by one principal and whose body arrived under another.
        let mut s = authenticating();
        run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
        s.authenticated(Some("alice".into()));
        assert_eq!(
            code(&run(&mut s, b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")),
            503
        );
    }

    #[test]
    fn auth_is_advertised_only_once_encrypted() {
        let mut s = Session::new("mx1.example.net", true, 1024).with_auth();
        let plain = run(&mut s, b"EHLO client.test\r\n");
        let Action::Reply(r) = &plain else { panic!() };
        assert!(
            !r.lines.iter().any(|l| l.contains("AUTH")),
            "AUTH advertised before TLS: {r:?}"
        );

        run(&mut s, b"STARTTLS\r\n");
        s.tls_established();
        let encrypted = run(&mut s, b"EHLO client.test\r\n");
        let Action::Reply(r) = &encrypted else {
            panic!()
        };
        assert!(
            r.lines.iter().any(|l| l.contains("AUTH PLAIN LOGIN")),
            "{r:?}"
        );
    }

    #[test]
    fn base64_decoding_accepts_what_clients_send() {
        assert_eq!(decode_base64("YWxpY2U="), Some("alice".into()));
        // Padding absent, which some clients omit.
        assert_eq!(decode_base64("YWxpY2U"), Some("alice".into()));
        // Whitespace, which others insert.
        assert_eq!(decode_base64("YWxp Y2U="), Some("alice".into()));
        assert_eq!(decode_base64(""), Some(String::new()));
        // Not base64 at all.
        assert_eq!(decode_base64("!!!"), None);
        // Valid base64, invalid UTF-8: not a password anything here can set.
        assert_eq!(decode_base64("//8="), None);
    }

    #[test]
    fn starttls_refused_during_a_transaction() {
        // TLS may not be negotiated with a transaction open: the sender and
        // recipients already accepted in plaintext would otherwise carry into
        // the encrypted session.
        let mut s = session();
        run(&mut s, b"EHLO client.example.org\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(code(&run(&mut s, b"STARTTLS\r\n")), 503);

        // Still available once the transaction is abandoned.
        run(&mut s, b"RSET\r\n");
        assert!(matches!(run(&mut s, b"STARTTLS\r\n"), Action::StartTls(_)));
    }

    #[test]
    fn starttls_discards_everything_learned_beforehand() {
        let mut s = session();
        run(&mut s, b"EHLO client.example.org\r\n");
        assert_eq!(s.peer_name(), Some("client.example.org"));

        let action = run(&mut s, b"STARTTLS\r\n");
        assert!(matches!(action, Action::StartTls(_)));
        assert_eq!(code(&action), 220);

        s.tls_established();

        // Greeting, sender and state must all be gone: anything injected in
        // plaintext before the handshake must not survive into the TLS session.
        assert_eq!(s.state(), State::Greeting);
        assert_eq!(s.peer_name(), None);
        assert!(s.envelope().sender.is_empty());
        assert!(s.is_tls());
        // The client has to greet again before doing anything.
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<a@b.com>\r\n")), 503);
    }

    #[test]
    fn starttls_not_offered_twice() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"STARTTLS\r\n");
        s.tls_established();
        run(&mut s, b"EHLO c\r\n");
        assert_eq!(code(&run(&mut s, b"STARTTLS\r\n")), 503);
    }

    #[test]
    fn starttls_absent_when_tls_unavailable() {
        let mut s = Session::new("mx1.example.net", false, 50 * 1024 * 1024);
        let action = run(&mut s, b"EHLO c\r\n");
        match action {
            Action::Reply(r) => {
                assert!(!r.lines.iter().any(|l| l.contains("STARTTLS")));
            }
            _ => panic!("expected reply"),
        }
        assert_eq!(code(&run(&mut s, b"STARTTLS\r\n")), 454);
    }

    #[test]
    fn does_not_advertise_what_it_refuses() {
        // The command parser rejects non-ASCII, so advertising SMTPUTF8 would
        // invite senders to use internationalised addresses and then refuse
        // them. An advertisement is a promise.
        let mut s = session();
        match run(&mut s, b"EHLO c\r\n") {
            Action::Reply(r) => {
                assert!(!r.lines.iter().any(|l| l.contains("SMTPUTF8")));
                // SIZE lets a sender skip transmitting what will be refused.
                assert!(
                    r.lines.iter().any(|l| l.as_ref() == "SIZE 52428800"),
                    "SIZE not advertised: {:?}",
                    r.lines
                );
            }
            _ => panic!("expected reply"),
        }
    }

    #[test]
    fn repeated_recipients_are_recorded_once() {
        // Accepted, as the specification requires, but not duplicated: a
        // hundred repeats would otherwise mean a hundred deliveries of one
        // message to one mailbox.
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(code(&run(&mut s, b"RCPT TO:<dup@example.net>\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<dup@example.net>\r\n")), 250);
        // Domain case folds; the local part does not.
        assert_eq!(code(&run(&mut s, b"RCPT TO:<dup@EXAMPLE.NET>\r\n")), 250);
        assert_eq!(s.envelope().recipients.len(), 1);
    }

    #[test]
    fn local_part_case_makes_a_distinct_recipient() {
        // RFC 5321 §2.4: only the destination host may interpret a local part.
        // Folding it here would answer 250 for `Dup@` and then silently drop
        // it — and with no retained copy and no bounce, that mail is simply
        // gone. An earlier version of this test asserted the opposite.
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(code(&run(&mut s, b"RCPT TO:<dup@example.net>\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<Dup@example.net>\r\n")), 250);
        assert_eq!(
            s.envelope().recipients,
            vec!["dup@example.net", "Dup@example.net"],
            "merged two distinct mailboxes"
        );
    }

    #[test]
    fn oversized_declaration_is_refused_before_the_body() {
        // Advertising SIZE and ignoring the parameter makes the advertisement
        // a lie, and costs the sender a full transmission to discover it.
        let mut s = Session::new("mx1.example.net", false, 1000);
        run(&mut s, b"EHLO c\r\n");
        assert_eq!(
            code(&run(&mut s, b"MAIL FROM:<a@b.com> SIZE=999999\r\n")),
            552
        );
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<a@b.com> SIZE=500\r\n")), 250);
        // Keywords are case-insensitive.
        run(&mut s, b"RSET\r\n");
        assert_eq!(
            code(&run(&mut s, b"MAIL FROM:<a@b.com> size=999999\r\n")),
            552
        );
    }

    #[test]
    fn refused_recipients_are_capped_over_the_whole_connection() {
        // The realistic harvest interleaves a successful command after every
        // refusal. An earlier version of this test issued the refusals back to
        // back, which is the one pattern a resettable counter catches — so it
        // passed while the wire behaviour was unbounded.
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");

        let mut last = None;
        for _ in 0..MAX_REFUSALS {
            last = Some(s.recipient_refused());
            // The thing that defeated the previous fix.
            run(&mut s, b"NOOP\r\n");
        }

        let last = last.unwrap();
        assert!(
            matches!(last, Action::Close(_)),
            "harvesting was never cut off"
        );
        assert_eq!(code(&last), 421);
    }

    #[test]
    fn occasional_stale_addresses_do_not_close_the_connection() {
        // The cap must sit well above what ordinary mail produces, or a sender
        // with a few dead addresses in its list gets hung up on.
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        for _ in 0..(MAX_REFUSALS - 1) {
            assert_eq!(code(&s.recipient_refused()), 550);
        }
        assert_ne!(s.state(), State::Closed);
    }

    #[test]
    fn malformed_addresses_are_refused() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<not-an-address>\r\n")), 501);
        // The null sender is valid and is not an address, so it is exempt.
        assert_eq!(code(&run(&mut s, b"MAIL FROM:<>\r\n")), 250);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<garbage>\r\n")), 501);
        assert_eq!(code(&run(&mut s, b"RCPT TO:<ok@example.net>\r\n")), 250);
        assert_eq!(s.envelope().recipients, vec!["ok@example.net"]);
    }

    #[test]
    fn errors_are_counted_consecutively_not_cumulatively() {
        // A long-lived connection collects occasional errors between good
        // traffic. Dropping it for that punishes the senders worth keeping.
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        for _ in 0..(MAX_ERRORS * 3) {
            assert_eq!(code(&run(&mut s, b"NONSENSE\r\n")), 500);
            assert_eq!(code(&run(&mut s, b"NOOP\r\n")), 250);
        }
        assert_ne!(
            s.state(),
            State::Closed,
            "dropped a client that kept recovering"
        );
    }

    #[test]
    fn ehlo_advertises_starttls_before_tls() {
        let mut s = session();
        match run(&mut s, b"EHLO c\r\n") {
            Action::Reply(r) => assert!(r.lines.iter().any(|l| l.contains("STARTTLS"))),
            _ => panic!("expected reply"),
        }
    }

    #[test]
    fn persistent_garbage_closes_the_connection() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        let mut last = None;
        for _ in 0..MAX_ERRORS {
            last = Some(run(&mut s, b"NONSENSE\r\n"));
        }
        let last = last.unwrap();
        assert!(matches!(last, Action::Close(_)));
        assert_eq!(code(&last), 421);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn quit_closes_before_greeting() {
        let mut s = session();
        let action = run(&mut s, b"QUIT\r\n");
        assert!(matches!(action, Action::Close(_)));
        assert_eq!(code(&action), 221);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn quit_closes_mid_transaction() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        run(&mut s, b"RCPT TO:<c@d.com>\r\n");
        let action = run(&mut s, b"QUIT\r\n");
        assert!(matches!(action, Action::Close(_)));
        assert_eq!(code(&action), 221);
        assert_eq!(s.state(), State::Closed);
    }

    #[test]
    fn oversized_body_clears_the_transaction() {
        let mut s = session();
        run(&mut s, b"EHLO c\r\n");
        run(&mut s, b"MAIL FROM:<a@b.com>\r\n");
        run(&mut s, b"RCPT TO:<c@d.com>\r\n");
        run(&mut s, b"DATA\r\n");
        let done = s.data_received(Err(DataError::TooLarge));
        assert_eq!(code(&done), 552);
        assert_eq!(s.state(), State::Ready);
        assert!(s.envelope().recipients.is_empty());
    }
}
