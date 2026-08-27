//! Email address parsing that borrows from the input buffer.

use std::fmt;

/// A borrowed, already-validated email address.
///
/// Holds two subslices of the caller's buffer and never allocates. Use this on
/// the SMTP hot path, where an envelope is parsed and matched against the
/// routing snapshot without producing a single `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address<'a> {
    local: &'a str,
    domain: &'a str,
}

/// Reasons an address failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// No `@` separator present.
    MissingAt,
    /// Local part was empty or exceeded 64 octets.
    InvalidLocalPart,
    /// Domain was empty or exceeded 255 octets.
    InvalidDomain,
    /// The address contained a control character, which could break out of the
    /// headers and commands it is later written into.
    ControlCharacter,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MissingAt => "address has no '@' separator",
            Self::InvalidLocalPart => "invalid local part",
            Self::InvalidDomain => "invalid domain",
            Self::ControlCharacter => "address contains a control character",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AddressError {}

impl<'a> Address<'a> {
    /// Parse an address without copying. The result borrows from `raw`.
    ///
    /// Control characters are refused. A bare CR survives command framing —
    /// only the *trailing* terminator is stripped — and an address carrying one
    /// is later interpolated into a `Received:` header and into outbound
    /// `RCPT TO:` commands. A lenient downstream parser treating that CR as a
    /// line break would see a forged header or an injected command.
    pub fn parse(raw: &'a str) -> Result<Self, AddressError> {
        // rsplit: the last '@' separates local part from domain, so quoted
        // local parts containing '@' still resolve correctly.
        // Checked across the whole input so neither half can smuggle one in.
        if raw.bytes().any(|b| b.is_ascii_control()) {
            return Err(AddressError::ControlCharacter);
        }

        let (local, domain) = raw.rsplit_once('@').ok_or(AddressError::MissingAt)?;

        if local.is_empty() || local.len() > 64 {
            return Err(AddressError::InvalidLocalPart);
        }
        if domain.is_empty() || domain.len() > 255 {
            return Err(AddressError::InvalidDomain);
        }
        // `>` and whitespace reach here through the unbracketed path form and
        // would break out of the `for <...>` clause of a trace header. Checked
        // separately from the syntax rules below so the intent survives if
        // those are ever relaxed.
        if local.bytes().any(|b| b == b'>' || b == b'<') {
            return Err(AddressError::InvalidLocalPart);
        }

        if !is_valid_domain(domain) {
            return Err(AddressError::InvalidDomain);
        }
        if !is_valid_local_part(local) {
            return Err(AddressError::InvalidLocalPart);
        }

        Ok(Self { local, domain })
    }

    /// The part before the `@`, as written.
    #[inline]
    pub fn local(&self) -> &'a str {
        self.local
    }

    /// The part after the `@`, as written.
    #[inline]
    pub fn domain(&self) -> &'a str {
        self.domain
    }

    /// The local part with any `+tag` suffix removed.
    ///
    /// Returns a borrowed subslice, so plus-address stripping stays allocation
    /// free. `hello+github` becomes `hello`; `hello` is returned unchanged.
    #[inline]
    pub fn local_without_tag(&self) -> &'a str {
        match self.local.split_once('+') {
            Some((base, _)) if !base.is_empty() => base,
            _ => self.local,
        }
    }

    /// Whether two addresses denote the same mailbox.
    ///
    /// The domain is compared case-insensitively; the local part is not.
    ///
    /// RFC 5321 §2.4 is explicit that a local part may be interpreted only by
    /// the host named in the domain, and that relays must preserve its case.
    /// `Bob@x.com` and `bob@x.com` may well be different people, and a relay
    /// has no way to know. Folding both halves looks harmless and quietly
    /// merges distinct recipients — which, for a forwarder that keeps no copy,
    /// means one of them never receives their mail and nobody is told.
    pub fn same_mailbox(&self, other: &Address<'_>) -> bool {
        self.local == other.local && self.domain.eq_ignore_ascii_case(other.domain)
    }

    /// Copy into an owned address for storage or cross-task use.
    pub fn to_owned_address(&self) -> AddressBuf {
        AddressBuf {
            local: self.local.to_owned(),
            domain: self.domain.to_ascii_lowercase(),
        }
    }
}

/// Whether a domain is syntactically usable as a mail destination.
///
/// A length check and a `contains('.')` are not enough: `x@.` passes both, and
/// a destination like that is accepted at startup, resolves to nothing, and
/// makes every forward fail. Labels are validated individually — non-empty, at
/// most 63 octets, letters, digits and hyphens, and no leading or trailing
/// hyphen.
///
/// Address literals (`[192.0.2.1]`, `[IPv6:...]`) are refused. They are legal
/// RFC 5321 and Pigeon has no use for them: a forwarder resolves MX records for
/// named domains, and accepting a form nothing downstream handles only moves
/// the failure later. Revisit if a real destination ever needs one.
fn is_valid_domain(domain: &str) -> bool {
    // A single label is not a mail domain. This also rejects the trailing-root
    // form `example.com.`, whose final label is empty.
    if !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Whether a local part is syntactically valid per RFC 5321 §4.1.2.
///
/// Two accepted forms. A quoted string carries almost anything, which is why
/// `"odd@name"@example.com` parses at all. An unquoted dot-string is limited to
/// `atext` plus interior dots — so `a b@example.com`, which a naive length
/// check admits, is refused here: the space would end the address in every
/// command and header it is later written into.
fn is_valid_local_part(local: &str) -> bool {
    if local.starts_with('"') {
        return is_valid_quoted_string(local);
    }

    // No leading dot, no trailing dot, no empty interior label.
    !local.split('.').any(|atom| {
        atom.is_empty()
            || !atom
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b))
    })
}

/// Whether a local part is a well-formed quoted string.
///
/// Must open and close with `"`, and any interior `"` or `\` must be escaped.
/// An unterminated quote is refused rather than tolerated: `"a@example.com`
/// would otherwise be read as a quoted local part running to the end of the
/// input, which is how a parser disagreement becomes an address two systems
/// read differently.
fn is_valid_quoted_string(local: &str) -> bool {
    let inner = match local.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        // `local.len() > 1` excludes a lone `"`, which strips to itself.
        Some(inner) if local.len() > 1 => inner,
        _ => return false,
    };

    let mut escaped = false;
    for b in inner.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'"' => return false,
            // Printable ASCII only; control characters were refused earlier.
            0x20..=0x7e => {}
            _ => return false,
        }
    }
    // A trailing backslash escapes the closing quote, leaving it unterminated.
    !escaped
}

impl fmt::Display for Address<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// An owned address, for values that must outlive the parse buffer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AddressBuf {
    local: String,
    domain: String,
}

impl AddressBuf {
    /// Borrow this owned address back as an [`Address`].
    #[inline]
    pub fn as_address(&self) -> Address<'_> {
        Address {
            local: &self.local,
            domain: &self.domain,
        }
    }

    #[inline]
    pub fn local(&self) -> &str {
        &self.local
    }

    #[inline]
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

impl fmt::Display for AddressBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_borrows() {
        let raw = String::from("hello@example.com");
        let addr = Address::parse(&raw).unwrap();
        assert_eq!(addr.local(), "hello");
        assert_eq!(addr.domain(), "example.com");
        // Borrowed, not copied.
        assert!(std::ptr::eq(addr.local().as_ptr(), raw.as_ptr()));
    }

    #[test]
    fn strips_plus_tag() {
        assert_eq!(
            Address::parse("hello+github@example.com")
                .unwrap()
                .local_without_tag(),
            "hello"
        );
        assert_eq!(
            Address::parse("hello@example.com")
                .unwrap()
                .local_without_tag(),
            "hello"
        );
        // A leading '+' is a real local part, not an empty base.
        assert_eq!(
            Address::parse("+tag@example.com")
                .unwrap()
                .local_without_tag(),
            "+tag"
        );
    }

    #[test]
    fn splits_on_last_at() {
        let addr = Address::parse(r#""odd@name"@example.com"#).unwrap();
        assert_eq!(addr.domain(), "example.com");
    }

    #[test]
    fn local_part_case_distinguishes_mailboxes() {
        // RFC 5321 §2.4: only the domain may be folded. A relay cannot know
        // whether Bob and bob are the same person, so it must not decide.
        let a = Address::parse("bob@example.com").unwrap();
        let b = Address::parse("Bob@example.com").unwrap();
        let c = Address::parse("bob@EXAMPLE.COM").unwrap();

        assert!(!a.same_mailbox(&b), "folded the local part");
        assert!(a.same_mailbox(&c), "failed to fold the domain");
        assert!(a.same_mailbox(&a));
    }

    #[test]
    fn rejects_malformed_domains() {
        // `x@.` passed a length check and a `contains('.')` check, which is
        // exactly how it reached the startup guard: a destination that is
        // accepted, resolves to nothing, and fails every forward.
        for raw in [
            "x@.",
            "x@..",
            "x@.com",
            "x@com.",
            "x@example..com",
            "x@-example.com",
            "x@example-.com",
            "x@example",
            "x@exa mple.com",
            "x@[192.0.2.1]",
        ] {
            assert_eq!(
                Address::parse(raw),
                Err(AddressError::InvalidDomain),
                "accepted malformed domain: {raw:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_local_parts() {
        // An unquoted space ends the address in every command and header it is
        // later written into, so the two ends of a relay disagree about where
        // the address stops.
        for raw in [
            "a b@example.com",
            ".leading@example.com",
            "trailing.@example.com",
            "double..dot@example.com",
            "\"unterminated@example.com",
            "\"bad\"quote\"@example.com",
            "a,b@example.com",
        ] {
            assert_eq!(
                Address::parse(raw),
                Err(AddressError::InvalidLocalPart),
                "accepted malformed local part: {raw:?}"
            );
        }
    }

    #[test]
    fn accepts_ordinary_and_quoted_forms() {
        // Tightening validation must not start refusing legitimate mail.
        for raw in [
            "hello@example.com",
            "first.last@sub.example.co.uk",
            "hello+tag@example.com",
            "user_name-1@example.com",
            "!#$%&'*+-/=?^_`{|}~@example.com",
            "\"odd@name\"@example.com",
            "\"quoted space\"@example.com",
            "\"esc\\\\aped\"@example.com",
            "x@a-b.example.com",
        ] {
            assert!(
                Address::parse(raw).is_ok(),
                "refused a valid address: {raw:?}"
            );
        }
    }

    #[test]
    fn rejects_control_characters() {
        // A bare CR survives command framing and would be interpolated into a
        // Received header and into outbound RCPT TO commands.
        assert_eq!(
            Address::parse("a\r@example.com"),
            Err(AddressError::ControlCharacter)
        );
        assert_eq!(
            Address::parse("a@exa\rmple.com"),
            Err(AddressError::ControlCharacter)
        );
        assert_eq!(
            Address::parse("a\n@example.com"),
            Err(AddressError::ControlCharacter)
        );
        assert_eq!(
            Address::parse("a\0@example.com"),
            Err(AddressError::ControlCharacter)
        );
    }

    #[test]
    fn rejects_angle_brackets_that_would_escape_a_trace_header() {
        // Reachable through the unbracketed path form, and lands inside the
        // `for <...>` clause of the Received header.
        assert!(Address::parse("a>x@example.com").is_err());
        assert!(Address::parse("a@example.com>x").is_err());
        assert!(Address::parse("a@exam ple.com").is_err());
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Address::parse("no-at-sign"), Err(AddressError::MissingAt));
        assert_eq!(
            Address::parse("@example.com"),
            Err(AddressError::InvalidLocalPart)
        );
        assert_eq!(Address::parse("hello@"), Err(AddressError::InvalidDomain));
        assert_eq!(
            Address::parse("hello@localhost"),
            Err(AddressError::InvalidDomain)
        );
    }
}
