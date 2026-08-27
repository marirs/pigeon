//! SMTP command parsing.
//!
//! Parsing borrows from the caller's line buffer and allocates nothing. A
//! command is two or three subslices of bytes that already exist.

use std::fmt;

/// Maximum length of a command line including CRLF (RFC 5321 §4.5.3.1.4).
///
/// The text of a command line is limited to 512 octets. Longer lines are
/// rejected rather than truncated: truncation would silently change the meaning
/// of a command, which is worse than refusing it.
pub const MAX_COMMAND_LINE: usize = 512;

/// A parsed SMTP command, borrowing from the input line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command<'a> {
    /// Extended greeting. Carries the client's claimed identity.
    Ehlo(&'a str),
    /// Original greeting. Carries the client's claimed identity.
    Helo(&'a str),
    /// Begins a transaction. An empty `path` is the null sender, `<>`, used by
    /// bounces — it is valid and must not be confused with a parse failure.
    Mail { path: &'a str, params: &'a str },
    /// Adds a recipient to the current transaction.
    Rcpt { path: &'a str, params: &'a str },
    /// Client is about to send the message body.
    Data,
    /// Abandon the current transaction.
    Rset,
    /// Do nothing.
    Noop,
    /// End the session.
    Quit,
    /// Begin TLS negotiation (RFC 3207).
    StartTls,
}

/// Why a command line could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The line was empty once its terminator was removed.
    Empty,
    /// The line exceeded [`MAX_COMMAND_LINE`].
    TooLong,
    /// The line contained bytes outside ASCII.
    NotAscii,
    /// The line carried a control character in its interior.
    ///
    /// Separate from [`ParseError::NotAscii`] because CR, LF and NUL *are*
    /// ASCII, and they are the ones that matter: the framing layer strips only
    /// the trailing terminator, so an interior CR survives into every value
    /// this parser returns.
    ControlCharacter,
    /// The verb is not one Pigeon implements.
    UnknownCommand,
    /// The verb is known but its arguments are malformed.
    Syntax,
    /// The verb requires an argument that was not supplied.
    MissingArgument,
    /// The verb takes no argument but one was supplied.
    UnexpectedArgument,
    /// A `MAIL` or `RCPT` path could not be read.
    InvalidPath,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Empty => "empty command",
            Self::TooLong => "command line too long",
            Self::NotAscii => "command contained non-ASCII bytes",
            Self::ControlCharacter => "command contained a control character",
            Self::UnknownCommand => "unrecognised command",
            Self::Syntax => "syntax error in parameters",
            Self::MissingArgument => "command requires an argument",
            Self::UnexpectedArgument => "command takes no argument",
            Self::InvalidPath => "malformed address path",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ParseError {}

impl<'a> Command<'a> {
    /// Whether this command is permitted before the client has greeted.
    ///
    /// Everything else earns a 503 until EHLO or HELO has been accepted.
    #[inline]
    pub fn allowed_before_greeting(&self) -> bool {
        matches!(
            self,
            Self::Ehlo(_) | Self::Helo(_) | Self::Quit | Self::Noop | Self::Rset
        )
    }
}

impl Command<'_> {
    /// Whether a `MAIL` path is the null sender used by bounce messages.
    #[inline]
    pub fn is_null_sender(path: &str) -> bool {
        path.is_empty()
    }
}

/// Parse one command line.
///
/// The line may or may not carry its `CRLF`; both are accepted, as is a bare
/// `LF`, because real clients send all three.
pub fn parse(line: &[u8]) -> Result<Command<'_>, ParseError> {
    if line.len() > MAX_COMMAND_LINE {
        return Err(ParseError::TooLong);
    }

    let line = strip_terminator(line);
    if line.is_empty() {
        return Err(ParseError::Empty);
    }

    // Verbs and arguments are ASCII. Checking up front means every later byte
    // index is a valid char boundary, so the slicing below cannot panic.
    if !line.is_ascii() {
        return Err(ParseError::NotAscii);
    }

    // No control characters anywhere in the line.
    //
    // `strip_terminator` removes only the *trailing* CRLF, so `EHLO a\rb`
    // arrives here with a bare CR in the middle and every value this function
    // returns is a borrow of it. Those values are interpolated into the
    // `Received:` header and into outbound `RCPT TO:` commands, where a CR is a
    // line break to any lenient parser — the header-injection primitive that
    // `Address::parse` was hardened against in finding 20a and that the EHLO
    // greeting kept, being hardened again at the header in finding 24a.
    //
    // Fixed here rather than at each consumer because that is what the previous
    // two attempts got wrong: sanitising at the point of use is a rule every
    // future caller has to remember, and `sanitise_for_header` was written
    // precisely because one did not. A `Command` now cannot hold one at all,
    // and the sanitiser stays as the second layer.
    //
    // Found by fuzzing, on the first run of the first target.
    if line.iter().any(|b| b.is_ascii_control()) {
        return Err(ParseError::ControlCharacter);
    }
    let text = std::str::from_utf8(line).map_err(|_| ParseError::NotAscii)?;

    let (verb, rest) = match text.find(' ') {
        Some(i) => (&text[..i], text[i + 1..].trim_start()),
        None => (text, ""),
    };

    if verb.eq_ignore_ascii_case("EHLO") {
        require_arg(rest).map(Command::Ehlo)
    } else if verb.eq_ignore_ascii_case("HELO") {
        require_arg(rest).map(Command::Helo)
    } else if verb.eq_ignore_ascii_case("MAIL") {
        let after = strip_prefix_ci(rest, "FROM:").ok_or(ParseError::Syntax)?;
        let (path, params) = parse_path(after)?;
        Ok(Command::Mail { path, params })
    } else if verb.eq_ignore_ascii_case("RCPT") {
        let after = strip_prefix_ci(rest, "TO:").ok_or(ParseError::Syntax)?;
        let (path, params) = parse_path(after)?;
        if path.is_empty() {
            // Unlike MAIL, an empty RCPT path is never meaningful.
            return Err(ParseError::InvalidPath);
        }
        Ok(Command::Rcpt { path, params })
    } else if verb.eq_ignore_ascii_case("DATA") {
        require_no_arg(rest).map(|_| Command::Data)
    } else if verb.eq_ignore_ascii_case("RSET") {
        require_no_arg(rest).map(|_| Command::Rset)
    } else if verb.eq_ignore_ascii_case("NOOP") {
        // NOOP is explicitly permitted to carry an ignored argument.
        Ok(Command::Noop)
    } else if verb.eq_ignore_ascii_case("QUIT") {
        require_no_arg(rest).map(|_| Command::Quit)
    } else if verb.eq_ignore_ascii_case("STARTTLS") {
        require_no_arg(rest).map(|_| Command::StartTls)
    } else {
        Err(ParseError::UnknownCommand)
    }
}

/// Remove a trailing `CRLF`, or a bare `LF`, if present.
fn strip_terminator(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
    }
    &line[..end]
}

/// Case-insensitive prefix strip. Safe on ASCII input only.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn require_arg(rest: &str) -> Result<&str, ParseError> {
    if rest.is_empty() {
        Err(ParseError::MissingArgument)
    } else {
        Ok(rest)
    }
}

fn require_no_arg(rest: &str) -> Result<(), ParseError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(ParseError::UnexpectedArgument)
    }
}

/// Split an address path from any trailing ESMTP parameters.
///
/// The bracketed form is the specified one. The bare form is accepted because
/// a meaningful share of real senders omit the brackets, and refusing them
/// loses legitimate mail to no benefit.
fn parse_path(s: &str) -> Result<(&str, &str), ParseError> {
    let s = s.trim_start();

    if let Some(rest) = s.strip_prefix('<') {
        let close = rest.find('>').ok_or(ParseError::InvalidPath)?;
        Ok((&rest[..close], rest[close + 1..].trim_start()))
    } else {
        if s.is_empty() {
            // Only the bracketed `<>` is the null sender. A bare empty path is
            // a truncated command.
            return Err(ParseError::InvalidPath);
        }
        match s.find(' ') {
            Some(i) => Ok((&s[..i], s[i + 1..].trim_start())),
            None => Ok((s, "")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_greetings() {
        assert_eq!(
            parse(b"EHLO mail.example.com\r\n"),
            Ok(Command::Ehlo("mail.example.com"))
        );
        assert_eq!(
            parse(b"HELO mail.example.com\r\n"),
            Ok(Command::Helo("mail.example.com"))
        );
    }

    #[test]
    fn verbs_are_case_insensitive() {
        assert_eq!(parse(b"ehlo host\r\n"), Ok(Command::Ehlo("host")));
        assert_eq!(parse(b"EhLo host\r\n"), Ok(Command::Ehlo("host")));
        assert_eq!(parse(b"quit\r\n"), Ok(Command::Quit));
    }

    #[test]
    fn accepts_all_three_line_endings() {
        assert_eq!(parse(b"QUIT\r\n"), Ok(Command::Quit));
        assert_eq!(parse(b"QUIT\n"), Ok(Command::Quit));
        assert_eq!(parse(b"QUIT"), Ok(Command::Quit));
    }

    #[test]
    fn parses_mail_from() {
        assert_eq!(
            parse(b"MAIL FROM:<sender@example.com>\r\n"),
            Ok(Command::Mail {
                path: "sender@example.com",
                params: ""
            })
        );
        // Parameter case and spacing after the colon both vary in the wild.
        assert_eq!(
            parse(b"mail from: <sender@example.com>\r\n"),
            Ok(Command::Mail {
                path: "sender@example.com",
                params: ""
            })
        );
    }

    #[test]
    fn null_sender_is_valid() {
        let cmd = parse(b"MAIL FROM:<>\r\n").unwrap();
        assert_eq!(
            cmd,
            Command::Mail {
                path: "",
                params: ""
            }
        );
        match cmd {
            Command::Mail { path, .. } => assert!(Command::is_null_sender(path)),
            _ => panic!("expected MAIL"),
        }
    }

    #[test]
    fn keeps_esmtp_parameters() {
        assert_eq!(
            parse(b"MAIL FROM:<a@example.com> SIZE=1024 BODY=8BITMIME\r\n"),
            Ok(Command::Mail {
                path: "a@example.com",
                params: "SIZE=1024 BODY=8BITMIME"
            })
        );
    }

    #[test]
    fn accepts_unbracketed_path() {
        assert_eq!(
            parse(b"RCPT TO:user@example.com\r\n"),
            Ok(Command::Rcpt {
                path: "user@example.com",
                params: ""
            })
        );
    }

    #[test]
    fn empty_rcpt_path_is_rejected() {
        // Valid for MAIL as the null sender, never valid for RCPT.
        assert_eq!(parse(b"RCPT TO:<>\r\n"), Err(ParseError::InvalidPath));
        assert_eq!(parse(b"RCPT TO:\r\n"), Err(ParseError::InvalidPath));
    }

    #[test]
    fn unterminated_bracket_is_rejected() {
        assert_eq!(
            parse(b"MAIL FROM:<a@example.com\r\n"),
            Err(ParseError::InvalidPath)
        );
    }

    #[test]
    fn wrong_keyword_is_a_syntax_error() {
        assert_eq!(
            parse(b"MAIL TO:<a@example.com>\r\n"),
            Err(ParseError::Syntax)
        );
        assert_eq!(
            parse(b"RCPT FROM:<a@example.com>\r\n"),
            Err(ParseError::Syntax)
        );
    }

    #[test]
    fn argument_requirements() {
        assert_eq!(parse(b"EHLO\r\n"), Err(ParseError::MissingArgument));
        assert_eq!(parse(b"DATA now\r\n"), Err(ParseError::UnexpectedArgument));
        // NOOP is specified to accept and ignore an argument.
        assert_eq!(parse(b"NOOP keepalive\r\n"), Ok(Command::Noop));
    }

    #[test]
    fn rejects_empty_and_unknown() {
        assert_eq!(parse(b"\r\n"), Err(ParseError::Empty));
        assert_eq!(parse(b""), Err(ParseError::Empty));
        assert_eq!(parse(b"WHAT\r\n"), Err(ParseError::UnknownCommand));
    }

    #[test]
    fn rejects_oversized_line() {
        let mut long = b"EHLO ".to_vec();
        long.resize(MAX_COMMAND_LINE + 1, b'a');
        assert_eq!(parse(&long), Err(ParseError::TooLong));
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        // Multi-byte input must not be indexed into mid-character.
        assert_eq!(
            parse("EHLO exämple.com\r\n".as_bytes()),
            Err(ParseError::NotAscii)
        );
        assert_eq!(parse(b"EHLO \xff\xfe\r\n"), Err(ParseError::NotAscii));
    }

    #[test]
    fn interior_control_characters_are_refused() {
        // `strip_terminator` removes only the trailing CRLF, so a bare CR in
        // the middle of a line used to survive into the greeting, the path and
        // the parameters — each of which is later written into a trace header
        // or an outbound command, where a lenient reader treats it as a line
        // break.
        //
        // Found by the first run of the first fuzz target, against a line the
        // existing tests had no reason to contain.
        assert_eq!(
            parse(b"EHLO mail.example.com\ri\r\n"),
            Err(ParseError::ControlCharacter)
        );
        assert_eq!(
            parse(b"MAIL FROM:<a\rb@example.com>\r\n"),
            Err(ParseError::ControlCharacter)
        );
        assert_eq!(
            parse(b"RCPT TO:<a@example.com>\rNOOP\r\n"),
            Err(ParseError::ControlCharacter)
        );
        assert_eq!(parse(b"NOOP\x00\r\n"), Err(ParseError::ControlCharacter));

        // The trailing terminator itself is not an interior control character,
        // and a line with no terminator at all is still fine.
        assert!(parse(b"EHLO mail.example.com\r\n").is_ok());
        assert!(parse(b"EHLO mail.example.com\n").is_ok());
        assert!(parse(b"EHLO mail.example.com").is_ok());
    }

    #[test]
    fn parse_borrows_rather_than_copies() {
        let line = b"EHLO mail.example.com\r\n";
        match parse(line).unwrap() {
            Command::Ehlo(host) => {
                assert!(std::ptr::eq(host.as_ptr(), line[5..].as_ptr()));
            }
            _ => panic!("expected EHLO"),
        }
    }

    #[test]
    fn greeting_gate() {
        assert!(parse(b"EHLO h\r\n").unwrap().allowed_before_greeting());
        assert!(parse(b"QUIT\r\n").unwrap().allowed_before_greeting());
        assert!(!parse(b"DATA\r\n").unwrap().allowed_before_greeting());
        assert!(
            !parse(b"MAIL FROM:<a@b.com>\r\n")
                .unwrap()
                .allowed_before_greeting()
        );
    }
}
