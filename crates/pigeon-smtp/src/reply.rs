//! SMTP replies.
//!
//! One allocation per reply at most, and none for the canned ones. Replies are
//! emitted once per command rather than per byte, so this is not a hot path.

use std::borrow::Cow;
use std::fmt;

/// A reply: one status code and one or more lines of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<Cow<'static, str>>,
}

impl Reply {
    /// A single-line reply from static text. Allocates only the `Vec`.
    pub fn line(code: u16, text: &'static str) -> Self {
        Self { code, lines: vec![Cow::Borrowed(text)] }
    }

    /// A single-line reply from owned text.
    pub fn owned(code: u16, text: String) -> Self {
        Self { code, lines: vec![Cow::Owned(text)] }
    }

    /// A multi-line reply, used for the EHLO capability list.
    pub fn multi(code: u16, lines: Vec<Cow<'static, str>>) -> Self {
        Self { code, lines }
    }

    /// Whether this reply reports failure.
    #[inline]
    pub fn is_error(&self) -> bool {
        self.code >= 400
    }

    /// Whether the failure is permanent, so the client must not retry.
    #[inline]
    pub fn is_permanent(&self) -> bool {
        self.code >= 500
    }

    /// Serialise in wire format.
    ///
    /// Continuation lines use `code-text`; the final line uses `code text`.
    /// Getting that separator wrong makes a client either hang waiting for more
    /// lines or truncate the reply, so it is worth a test of its own.
    pub fn to_wire(&self) -> String {
        let mut out = String::with_capacity(self.lines.len() * 40);
        let last = self.lines.len().saturating_sub(1);
        for (i, line) in self.lines.iter().enumerate() {
            let sep = if i == last { ' ' } else { '-' };
            out.push_str(&self.code.to_string());
            out.push(sep);
            out.push_str(line);
            out.push_str("\r\n");
        }
        out
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

// Canned replies.

pub fn service_ready(hostname: &str) -> Reply {
    Reply::owned(220, format!("{hostname} Pigeon ESMTP ready"))
}

pub fn ehlo_ok(hostname: &str, extensions: &[&'static str]) -> Reply {
    ehlo_ok_owned(hostname, extensions.iter().map(|e| Cow::Borrowed(*e)).collect())
}

/// As [`ehlo_ok`], for capability lines computed at runtime such as `SIZE`.
pub fn ehlo_ok_owned(hostname: &str, extensions: Vec<Cow<'static, str>>) -> Reply {
    let mut lines: Vec<Cow<'static, str>> = Vec::with_capacity(extensions.len() + 1);
    lines.push(Cow::Owned(format!("{hostname} greets you")));
    lines.extend(extensions);
    Reply::multi(250, lines)
}

pub fn ok() -> Reply {
    Reply::line(250, "Ok")
}

pub fn bye(hostname: &str) -> Reply {
    Reply::owned(221, format!("{hostname} closing connection"))
}

pub fn start_mail_input() -> Reply {
    Reply::line(354, "End data with <CR><LF>.<CR><LF>")
}

pub fn tls_ready() -> Reply {
    Reply::line(220, "Ready to start TLS")
}

/// Accepted and durably queued. Sent only once the message can survive a crash.
pub fn queued(id: &str) -> Reply {
    Reply::owned(250, format!("Ok: queued as {id}"))
}

pub fn bad_sequence() -> Reply {
    Reply::line(503, "Bad sequence of commands")
}

pub fn syntax_error() -> Reply {
    Reply::line(501, "Syntax error in parameters or arguments")
}

pub fn command_unrecognised() -> Reply {
    Reply::line(500, "Syntax error, command unrecognised")
}

pub fn line_too_long() -> Reply {
    Reply::line(500, "Line too long")
}

pub fn no_such_user() -> Reply {
    Reply::line(550, "No such user here")
}

pub fn too_many_recipients() -> Reply {
    Reply::line(452, "Too many recipients")
}

pub fn message_too_large() -> Reply {
    Reply::line(552, "Message exceeds maximum size")
}

pub fn tls_required() -> Reply {
    Reply::line(530, "Must issue a STARTTLS command first")
}

pub fn tls_not_available() -> Reply {
    Reply::line(454, "TLS not available")
}

/// Temporary failure. The client should retry, and the message is not lost.
pub fn temporary_failure() -> Reply {
    Reply::line(451, "Requested action aborted: local error in processing")
}

pub fn timeout() -> Reply {
    Reply::line(421, "Timeout waiting for command")
}

pub fn too_many_errors() -> Reply {
    Reply::line(421, "Too many errors, closing connection")
}

/// Total session lifetime exceeded, regardless of activity.
///
/// Distinct from an idle timeout: this fires on a client that keeps talking
/// solely to hold its slot, which no per-command timeout can catch.
pub fn session_too_long() -> Reply {
    Reply::line(421, "Session too long, closing connection")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_uses_space_separator() {
        assert_eq!(ok().to_wire(), "250 Ok\r\n");
    }

    #[test]
    fn multiline_marks_continuations_with_hyphen() {
        let r = ehlo_ok("mx1.example.net", &["SIZE 52428800", "STARTTLS", "8BITMIME"]);
        assert_eq!(
            r.to_wire(),
            "250-mx1.example.net greets you\r\n\
             250-SIZE 52428800\r\n\
             250-STARTTLS\r\n\
             250 8BITMIME\r\n"
        );
    }

    #[test]
    fn ehlo_with_no_extensions_is_still_terminated() {
        let r = ehlo_ok("mx1.example.net", &[]);
        assert_eq!(r.to_wire(), "250 mx1.example.net greets you\r\n");
    }

    #[test]
    fn classifies_severity() {
        assert!(!ok().is_error());
        assert!(too_many_recipients().is_error());
        assert!(!too_many_recipients().is_permanent()); // 4xx: retry later
        assert!(no_such_user().is_permanent()); // 5xx: do not retry
    }

    #[test]
    fn every_line_ends_with_crlf() {
        for r in [ok(), bad_sequence(), start_mail_input(), ehlo_ok("h", &["A", "B"])] {
            let wire = r.to_wire();
            assert!(wire.ends_with("\r\n"));
            for line in wire.trim_end_matches("\r\n").split("\r\n") {
                assert!(line.len() >= 4, "reply line too short: {line:?}");
            }
        }
    }
}
