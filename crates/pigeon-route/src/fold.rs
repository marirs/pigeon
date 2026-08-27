//! ASCII case folding into a stack buffer.
//!
//! `pigeon-route` promises allocation-free lookup, and an incoming recipient
//! arrives in whatever case the sender used — so it has to be folded before it
//! can be used as a key, and `to_ascii_lowercase` allocates.
//!
//! `Address::parse` already bounds both halves: a local part is at most 64
//! octets and a domain at most 255, refused otherwise. Nothing longer can reach
//! a lookup, because nothing that failed to parse gets that far. So the buffers
//! here are not a guess — they are the limits the parser already enforces, and
//! a change to one is a change to the other.
//!
//! ASCII-only folding is correct rather than merely convenient: SMTPUTF8 is not
//! advertised (finding 2), so a local part is ASCII by the time it is parsed,
//! and domains are stored and received as A-labels.

/// Longest local part, matching `Address::parse`.
pub const MAX_LOCAL: usize = 64;

/// Longest domain, matching `Address::parse`.
pub const MAX_DOMAIN: usize = 255;

/// A lowercase copy of a bounded string, held on the stack.
pub struct Folded<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Folded<N> {
    /// Fold `s`, or return `None` if it is longer than this buffer.
    ///
    /// `None` is not an error to report to a sender — it means the caller
    /// skipped `Address::parse`, since a value this long cannot come from one.
    /// Callers treat it as "matches nothing", which is the safe direction.
    pub fn new(s: &str) -> Option<Self> {
        if s.len() > N {
            return None;
        }
        let mut buf = [0u8; N];
        for (i, b) in s.bytes().enumerate() {
            buf[i] = b.to_ascii_lowercase();
        }
        Some(Self { buf, len: s.len() })
    }

    pub fn as_str(&self) -> &str {
        // Folding ASCII case maps ASCII bytes to ASCII bytes and leaves every
        // other byte alone, so UTF-8 boundaries are preserved and this cannot
        // fail on input that was `&str` to begin with.
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// Fold a local part.
pub fn local(s: &str) -> Option<Folded<MAX_LOCAL>> {
    Folded::new(s)
}

/// Fold a domain.
pub fn domain(s: &str) -> Option<Folded<MAX_DOMAIN>> {
    Folded::new(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_ascii_case_only() {
        assert_eq!(local("Hello").unwrap().as_str(), "hello");
        assert_eq!(domain("EXAMPLE.COM").unwrap().as_str(), "example.com");
        assert_eq!(local("hello+GitHub").unwrap().as_str(), "hello+github");
    }

    #[test]
    fn leaves_non_alphabetic_bytes_alone() {
        assert_eq!(local("a.b-c_d+1").unwrap().as_str(), "a.b-c_d+1");
    }

    #[test]
    fn refuses_input_longer_than_the_parser_permits() {
        // A value this long cannot have come from `Address::parse`, so the
        // caller skipped it. Matching nothing is the safe direction.
        assert!(local(&"a".repeat(MAX_LOCAL + 1)).is_none());
        assert!(domain(&"a".repeat(MAX_DOMAIN + 1)).is_none());
        assert!(local(&"a".repeat(MAX_LOCAL)).is_some());
    }

    #[test]
    fn the_buffer_limits_match_the_parser() {
        // If these ever disagree, an address the parser accepted would silently
        // fail to fold and route nowhere.
        assert!(
            pigeon_types::Address::parse(&format!("{}@example.com", "a".repeat(MAX_LOCAL))).is_ok()
        );
        assert!(
            pigeon_types::Address::parse(&format!("{}@example.com", "a".repeat(MAX_LOCAL + 1)))
                .is_err()
        );
    }
}
