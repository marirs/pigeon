//! Alias patterns: the one-star grammar and its ordering.
//!
//! Design: `M1-SNAPSHOT.md` §2 and §3.

use std::cmp::Ordering;
use std::fmt;

/// Why a pattern is not usable as an alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    /// More than one `*`. See [`Wildcard`] for why the grammar is this small.
    TooManyStars(usize),
    /// A character that cannot appear in a local part.
    NotALocalPart(char),
    /// Longer than RFC 5321 permits for a local part.
    TooLong(usize),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("pattern is empty"),
            Self::TooManyStars(n) => write!(
                f,
                "pattern has {n} '*' characters; alias patterns take at most one"
            ),
            Self::NotALocalPart(c) => {
                write!(f, "{c:?} cannot appear in the local part of an address")
            }
            Self::TooLong(n) => write!(f, "pattern is {n} octets; the limit is 64"),
        }
    }
}

impl std::error::Error for PatternError {}

/// The longest local part RFC 5321 allows, and what `Address::parse` enforces.
pub const MAX_LOCAL: usize = 64;

/// A pattern with exactly one `*`, pre-split for matching.
///
/// # Why one star
///
/// A deliberately smaller grammar, chosen for the matcher and for the overlap
/// test — not for safety. An earlier draft claimed several stars would invite
/// catastrophic backtracking, which is false: a multi-star glob matches
/// linearly with a two-pointer scan. The claim read as a checked security
/// property, which is the most expensive kind of comment to leave standing.
///
/// The real reason is [`Wildcard::overlaps`]. With one star, deciding whether
/// two patterns can ever match the same address is a prefix and suffix
/// comparison and is exact. With several it becomes a search, and the
/// ambiguity rule in §7 — which *blocks publication* — would rest on an
/// approximation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wildcard {
    prefix: String,
    suffix: String,
    /// Kept for diagnostics and for the ordering, which compares patterns.
    source: String,
}

impl Wildcard {
    /// The literal text before the `*`.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The literal text after the `*`.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Literal, non-`*` characters. The primary ranking key (§2).
    pub fn literals(&self) -> usize {
        self.prefix.len() + self.suffix.len()
    }

    /// Whether this pattern matches a local part.
    ///
    /// The length guard is not an optimisation: without it, a prefix and a
    /// suffix that overlap in a short candidate would both match and the `*`
    /// would have consumed characters twice — `a*a` would match `a`.
    pub fn matches(&self, candidate: &str) -> bool {
        candidate.len() >= self.prefix.len() + self.suffix.len()
            && candidate.starts_with(&self.prefix)
            && candidate.ends_with(&self.suffix)
    }

    /// Whether some local part exists that both patterns match.
    ///
    /// Exact rather than approximate, and that is the whole reason the grammar
    /// has one star. The `*` absorbs any length, so a witness exists whenever
    /// both ends are compatible: take the longer prefix, enough filler to clear
    /// both minimum lengths, then the longer suffix.
    pub fn overlaps(&self, other: &Wildcard) -> bool {
        let prefix_ok =
            self.prefix.starts_with(&other.prefix) || other.prefix.starts_with(&self.prefix);
        let suffix_ok =
            self.suffix.ends_with(&other.suffix) || other.suffix.ends_with(&self.suffix);
        prefix_ok && suffix_ok
    }

    /// Precedence order: more literal characters first, then bytewise.
    ///
    /// The first draft ranked by pattern length and *then* literal count. With
    /// exactly one star those are the same number — literals is always length
    /// minus one — so the second criterion could never break a tie the first
    /// had not already broken. Two rules, one of them unreachable.
    ///
    /// The bytewise fallback is arbitrary and exists only to be total. It is
    /// documented as arbitrary so nobody reasons from it: a configuration where
    /// it would decide anything visible does not build (§7).
    pub fn precedence(&self, other: &Wildcard) -> Ordering {
        other
            .literals()
            .cmp(&self.literals())
            .then_with(|| self.source.cmp(&other.source))
    }
}

/// Parse an alias pattern, folded and validated.
///
/// Returns `Ok(None)` for an exact pattern (no `*`) and `Ok(Some(_))` for a
/// wildcard, so the caller cannot mix them up by accident.
pub fn parse(raw: &str) -> Result<Option<Wildcard>, PatternError> {
    if raw.is_empty() {
        return Err(PatternError::Empty);
    }
    if raw.len() > MAX_LOCAL {
        return Err(PatternError::TooLong(raw.len()));
    }

    let stars = raw.bytes().filter(|b| *b == b'*').count();
    if stars > 1 {
        return Err(PatternError::TooManyStars(stars));
    }

    // Every character that is not the wildcard must be one an address could
    // actually carry. A pattern containing a character no local part may hold
    // can never match anything, so it is a mistake rather than a dead rule.
    for c in raw.chars().filter(|c| *c != '*') {
        if !is_local_char(c) {
            return Err(PatternError::NotALocalPart(c));
        }
    }

    match raw.split_once('*') {
        None => Ok(None),
        Some((prefix, suffix)) => Ok(Some(Wildcard {
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
            source: raw.to_string(),
        })),
    }
}

/// Whether an exact pattern is a usable local part.
pub fn validate_exact(raw: &str) -> Result<(), PatternError> {
    match parse(raw)? {
        None => Ok(()),
        // A stored exact rule holding a `*` means the two kinds got confused
        // somewhere upstream, and it would silently never match.
        Some(w) => Err(PatternError::TooManyStars(
            w.as_str().bytes().filter(|b| *b == b'*').count(),
        )),
    }
}

/// `atext` from RFC 5321 §4.1.2, plus `.` for dot-strings.
///
/// Quoted local parts are not accepted as alias patterns. A quoted string can
/// hold almost anything including `@` and whitespace, and an alias is something
/// an operator types; the addresses that need one are vanishingly rare and the
/// grammar cost is permanent.
fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'+-/=?^_`{|}~.".contains(c)
}
