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
            refusals: 0,
            return_path: None,
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
        // Advertising STARTTLS once TLS is active would invite a client to
        // negotiate twice.
        if self.tls_available && !self.tls {
            ext.push(std::borrow::Cow::Borrowed("STARTTLS"));
        }
        Action::Reply(reply::ehlo_ok_owned(&self.hostname, ext))
    }

    fn mail(&mut self, path: &str, params: &str) -> Action {
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
