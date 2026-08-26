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
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MissingAt => "address has no '@' separator",
            Self::InvalidLocalPart => "invalid local part",
            Self::InvalidDomain => "invalid domain",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AddressError {}

impl<'a> Address<'a> {
    /// Parse an address without copying. The result borrows from `raw`.
    pub fn parse(raw: &'a str) -> Result<Self, AddressError> {
        // rsplit: the last '@' separates local part from domain, so quoted
        // local parts containing '@' still resolve correctly.
        let (local, domain) = raw.rsplit_once('@').ok_or(AddressError::MissingAt)?;

        if local.is_empty() || local.len() > 64 {
            return Err(AddressError::InvalidLocalPart);
        }
        if domain.is_empty() || domain.len() > 255 || !domain.contains('.') {
            return Err(AddressError::InvalidDomain);
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

    /// Copy into an owned address for storage or cross-task use.
    pub fn to_owned_address(&self) -> AddressBuf {
        AddressBuf {
            local: self.local.to_owned(),
            domain: self.domain.to_ascii_lowercase(),
        }
    }
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
        Address { local: &self.local, domain: &self.domain }
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
        assert_eq!(Address::parse("hello+github@example.com").unwrap().local_without_tag(), "hello");
        assert_eq!(Address::parse("hello@example.com").unwrap().local_without_tag(), "hello");
        // A leading '+' is a real local part, not an empty base.
        assert_eq!(Address::parse("+tag@example.com").unwrap().local_without_tag(), "+tag");
    }

    #[test]
    fn splits_on_last_at() {
        let addr = Address::parse(r#""odd@name"@example.com"#).unwrap();
        assert_eq!(addr.domain(), "example.com");
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Address::parse("no-at-sign"), Err(AddressError::MissingAt));
        assert_eq!(Address::parse("@example.com"), Err(AddressError::InvalidLocalPart));
        assert_eq!(Address::parse("hello@"), Err(AddressError::InvalidDomain));
        assert_eq!(Address::parse("hello@localhost"), Err(AddressError::InvalidDomain));
    }
}
