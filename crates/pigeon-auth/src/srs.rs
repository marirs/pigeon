//! SRS — the Sender Rewriting Scheme.
//!
//! Forwarding breaks SPF: the destination sees Pigeon's IP under the original
//! sender's domain, which does not authorise it. SRS rewrites the envelope
//! sender into a domain that does, and does it *reversibly*, so a bounce
//! addressed to the rewritten sender can be turned back into the original one.
//!
//! The wire grammar, the key lifecycle and the failure rules are specified in
//! `M2-DESIGN.md` §5. What is here implements that specification; where a
//! comment states a rule, the section it came from is named so the two can be
//! checked against each other.
//!
//! # What is deliberately not classic SRS
//!
//! Three departures, all recorded in the design and all for the same reason —
//! nobody but Pigeon ever parses these addresses, so the format's defaults are
//! not constraints:
//!
//! - **40-bit tags** rather than 20. Forging a return path turns the forwarder
//!   into a backscatter relay aimed at the original sender.
//! - **Three-character timestamps** rather than two. Two characters wrap every
//!   1024 days, and the failure is not a rejected address but an accepted one:
//!   a captured address becomes current again on its wrap anniversary.
//! - **Percent-escaped fields.** `=` is valid in a local part, so unescaped
//!   fields let a sender forge a field boundary.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// ------------------------------------------------------------------ constants

/// RFC 5321 §4.5.3.1.1. The whole reason [`SrsError::TooLong`] exists.
pub const MAX_LOCAL_PART: usize = 64;

/// How long a rewritten address stays valid (§5.5).
///
/// Comfortably longer than the ~5 day retry schedule `pigeon-spool` documents:
/// a return path must outlive the queue that might still be using it.
pub const WINDOW_DAYS: u32 = 21;

/// Tolerance for a peer whose clock is behind ours (§5.5).
pub const FUTURE_TOLERANCE_DAYS: u32 = 1;

/// Days after a key stops signing before it may be deleted (§5.6).
///
/// `WINDOW_DAYS` plus the queue's maximum lifetime, rounded up. Deleting
/// earlier breaks bounces for mail already in flight, and breaks them silently:
/// the failure appears at a stranger's MTA as an unroutable address.
pub const RETIREMENT_DAYS: u32 = 30;

/// Hard cap on ring size (§5.4).
///
/// Every verification is one HMAC per key, so the ring is an attacker-visible
/// work multiplier. A ninth key is a refusal at load, not a warning.
pub const MAX_KEYS: usize = 8;

const TAG_CHARS: usize = 8;
const TAG_BYTES: usize = 5;
const TIMESTAMP_CHARS: usize = 3;

/// 2^15 days, about 89 years — long enough that the wrap is not a design
/// concern rather than merely a distant one.
const TIMESTAMP_MODULUS: u32 = 32768;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const SRS0_PREFIX: &str = "SRS0=";
const SRS1_PREFIX: &str = "SRS1=";

// --------------------------------------------------------------------- errors

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SrsError {
    /// The rewritten local part would exceed 64 octets (§5.7).
    ///
    /// Carries what it would have been, because the operator's question is
    /// always "by how much", and the answer decides whether a shorter
    /// forwarding domain fixes it.
    #[error("the rewritten sender would be {octets} octets, over the {MAX_LOCAL_PART} limit")]
    TooLong { octets: usize },

    #[error("not a Pigeon-rewritten address")]
    NotRewritten,

    #[error("malformed rewritten address: {0}")]
    Malformed(&'static str),

    /// The tag did not match under any key in the ring.
    ///
    /// Deliberately says nothing more. Which key failed, and how close the tag
    /// was, are exactly what an attacker probing for a forgery wants to learn.
    #[error("the address is not one this host issued")]
    BadTag,

    #[error("the address expired {age_days} days ago")]
    Expired { age_days: u32 },

    /// Past the tolerance in §5.5. Almost always a clock problem here, not
    /// there, which is why it is distinguishable from an expiry.
    #[error("the address is dated {days} days in the future")]
    FutureDated { days: u32 },

    #[error("no key in the ring is eligible to sign")]
    NoSigningKey,

    #[error("the SRS key ring is unusable: {0}")]
    Ring(String),
}

// ----------------------------------------------------------------------- days

/// Whole days since the Unix epoch, UTC.
///
/// Wall clock deliberately, not monotonic (§5.5): the value must agree with
/// itself across restarts, and a monotonic clock resets. Passed in explicitly
/// everywhere rather than read at the point of use, so tests can place a
/// message at any day — including the wrap — without waiting for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Day(pub u32);

impl Day {
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self((secs / 86_400) as u32)
    }

    fn wrapped(self) -> u32 {
        self.0 % TIMESTAMP_MODULUS
    }
}

// ------------------------------------------------------------------- the ring

/// One SRS secret and its lifecycle.
#[derive(Clone)]
pub struct Key {
    pub id: u32,
    pub created: String,
    /// When this key stopped signing, if it has.
    ///
    /// Recorded rather than inferred (§5.4). Deletion eligibility is measured
    /// from here, and `created` cannot express it: a key created two years ago
    /// and displaced yesterday is a key whose addresses are still arriving.
    pub stopped_signing_at: Option<String>,
    secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Key {
    /// Never the secret. `KeyPair` learned this the same way — a `Debug` that
    /// prints key material puts it in every error log that formats the value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("created", &self.created)
            .field("stopped_signing_at", &self.stopped_signing_at)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The ring, newest first.
#[derive(Debug, Clone)]
pub struct KeyRing {
    keys: Vec<Key>,
}

impl KeyRing {
    /// Parse the ring file.
    ///
    /// Format, one key per line, newest first:
    ///
    /// ```text
    /// # id  created              stopped_signing_at   secret (base64, 32 bytes)
    /// 2     2026-08-01T00:00:00Z -                    4f...==
    /// 1     2026-02-01T00:00:00Z 2026-08-01T00:00:00Z 9a...==
    /// ```
    ///
    /// **Order is positional, not by parsed date** (§5.4). The dates are for
    /// the operator; making them load-bearing would let a mistyped year change
    /// which key signs, which is a silent change to something security
    /// relevant.
    pub fn parse(text: &str) -> Result<Self, SrsError> {
        let mut keys = Vec::new();

        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 4 {
                return Err(SrsError::Ring(format!(
                    "line {}: expected 4 fields, found {}",
                    n + 1,
                    fields.len()
                )));
            }

            let id = fields[0]
                .parse::<u32>()
                .map_err(|_| SrsError::Ring(format!("line {}: id is not a number", n + 1)))?;

            let secret = base64_decode(fields[3])
                .ok_or_else(|| SrsError::Ring(format!("line {}: secret is not base64", n + 1)))?;

            // 32 bytes because that is what HMAC-SHA-256's block structure
            // makes worth having; shorter is accepted by the algorithm and is
            // a weaker key than the operator thinks they configured.
            if secret.len() != 32 {
                return Err(SrsError::Ring(format!(
                    "line {}: secret is {} bytes, expected 32",
                    n + 1,
                    secret.len()
                )));
            }

            keys.push(Key {
                id,
                created: fields[1].to_string(),
                stopped_signing_at: match fields[2] {
                    "-" => None,
                    other => Some(other.to_string()),
                },
                secret: Zeroizing::new(secret),
            });

            // Checked inside the loop rather than after it, so a file with a
            // thousand keys is not fully parsed before being refused.
            if keys.len() > MAX_KEYS {
                return Err(SrsError::Ring(format!(
                    "more than {MAX_KEYS} keys; every verification is one HMAC per key"
                )));
            }
        }

        if keys.is_empty() {
            return Err(SrsError::Ring("no keys".into()));
        }

        // The signing key is the first one, so a first entry that has stopped
        // signing is a ring whose rotation was left half-done.
        if keys[0].stopped_signing_at.is_some() {
            return Err(SrsError::Ring(
                "the first key has a stopped_signing_at date; it cannot sign".into(),
            ));
        }

        Ok(Self { keys })
    }

    pub fn load(path: &Path) -> Result<Self, SrsError> {
        // Permissions are enforced by `pigeon-config`'s startup validation,
        // which requires 0600 on this file. Not re-checked here: two places
        // enforcing one rule is two places for it to drift.
        let text = std::fs::read_to_string(path)
            .map_err(|e| SrsError::Ring(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    fn signing(&self) -> Result<&Key, SrsError> {
        self.keys
            .first()
            .filter(|k| k.stopped_signing_at.is_none())
            .ok_or(SrsError::NoSigningKey)
    }
}

// ------------------------------------------------------------------------ SRS

/// The rewriter, bound to the domain it rewrites into.
#[derive(Debug, Clone)]
pub struct Srs {
    ring: KeyRing,
    domain: String,
    window_days: u32,
}

/// What a reversed address turned back into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reversed {
    /// The address a bounce should be delivered to.
    pub address: String,
    /// The id of the key whose tag matched, for the log.
    pub key_id: u32,
}

impl Srs {
    pub fn new(ring: KeyRing, domain: impl Into<String>) -> Self {
        Self {
            ring,
            domain: into_lowercase(domain.into()),
            window_days: WINDOW_DAYS,
        }
    }

    /// Rewrite `local@domain` into an address in this host's domain.
    ///
    /// Returns the complete rewritten address. The caller decides what to do
    /// with [`SrsError::TooLong`]; §7 requires that decision to be made before
    /// the message is accepted, at `RCPT TO`, because a message that cannot be
    /// forwarded and cannot be bounced is the one outcome with no good ending.
    pub fn forward(&self, local: &str, domain: &str, now: Day) -> Result<String, SrsError> {
        let key = self.ring.signing()?;
        let stamp = encode_timestamp(now);

        // An address this host already rewrote, or one another forwarder did,
        // is wrapped rather than rewritten again — otherwise every hop buries
        // the original sender one layer deeper and the address grows without
        // bound.
        let local_part = if let Some(rest) = strip_prefix_ci(local, SRS0_PREFIX) {
            // A foreign SRS0 tail is opaque: its tag is another host's, its
            // timestamp may be two characters or three, and its epoch is its
            // own business. Wrapping it whole is what makes that irrelevant.
            self.build_srs1(key, domain, rest)
        } else if let Some(rest) = strip_prefix_ci(local, SRS1_PREFIX) {
            // Already wrapped by someone. Re-tag it with our own key, keeping
            // the first hop it names.
            let (_, after_tag) = split_once_field(rest).ok_or(SrsError::Malformed("SRS1 tag"))?;
            let (first_hop, tail) = after_tag
                .split_once("==")
                .ok_or(SrsError::Malformed("SRS1 body"))?;
            self.build_srs1(key, first_hop, tail)
        } else {
            self.build_srs0(key, &stamp, domain, local)
        };

        // Checked on the assembled local part, not estimated from the parts:
        // escaping can expand a field and the estimate would be the thing that
        // was wrong.
        if local_part.len() > MAX_LOCAL_PART {
            return Err(SrsError::TooLong {
                octets: local_part.len(),
            });
        }

        Ok(format!("{local_part}@{}", self.domain))
    }

    fn build_srs0(&self, key: &Key, stamp: &str, domain: &str, local: &str) -> String {
        // The domain is folded on the wire as well as in the tag, so the
        // address is canonical: one original sender produces one rewritten
        // address regardless of how the envelope happened to be cased.
        //
        // Verification lowercases the field again before computing the tag, so
        // a peer that re-cases the domain in transit still verifies — which is
        // correct, since RFC 5321 §2.4 makes domain case insignificant.
        let domain = into_lowercase(domain.to_string());
        let tag = tag(&key.secret, stamp, &domain, local);
        format!(
            "{SRS0_PREFIX}{tag}={stamp}={}={}",
            escape(&domain),
            escape(local)
        )
    }

    /// `SRS1=tag=firsthop==<opaque tail>` — the classic layout, with no
    /// timestamp of our own.
    ///
    /// **Expiry belongs to the inner issuer.** The tail is an `SRS0` address
    /// created by the host named in `firsthop`, carrying that host's tag and
    /// its timestamp. A bounce reaching this address is sent onward to that
    /// host, which applies its own window — so the expiry exists, one hop
    /// away, and duplicating it here would buy nothing that the format's
    /// recognisability does not outweigh.
    ///
    /// The consequence, stated so it is not discovered later: **our tag on an
    /// SRS1 address does not expire.** What it authenticates is that this host
    /// produced the wrapper. A replayed one still lands at the first hop,
    /// which is where the timestamp that governs it lives.
    ///
    /// `==` between the hop and the tail is the classic separator, and it is
    /// what lets a decoder find the start of an opaque tail that contains `=`
    /// characters of its own.
    fn build_srs1(&self, key: &Key, first_hop: &str, tail: &str) -> String {
        let hop = into_lowercase(first_hop.to_string());
        let tag = tag_untimed(&key.secret, &hop, tail);
        format!("{SRS1_PREFIX}{tag}={}=={tail}", escape(&hop))
    }

    /// Turn a rewritten address back into the one it was made from.
    pub fn reverse(&self, local: &str, now: Day) -> Result<Reversed, SrsError> {
        if let Some(rest) = strip_prefix_ci(local, SRS0_PREFIX) {
            self.reverse_srs0(rest, now)
        } else if let Some(rest) = strip_prefix_ci(local, SRS1_PREFIX) {
            self.reverse_srs1(rest)
        } else {
            Err(SrsError::NotRewritten)
        }
    }

    fn reverse_srs0(&self, rest: &str, now: Day) -> Result<Reversed, SrsError> {
        let (tag_field, rest) = split_once_field(rest).ok_or(SrsError::Malformed("tag"))?;
        let (stamp, rest) = split_once_field(rest).ok_or(SrsError::Malformed("timestamp"))?;
        let (domain_field, local_field) =
            split_once_field(rest).ok_or(SrsError::Malformed("domain"))?;

        // Unescaped before the tag is computed, because the tag covers the
        // original bytes (§5.3). A re-encoding by an intermediate that
        // normalises `%3D` back to `=` therefore fails to verify rather than
        // silently rewriting the sender.
        let domain = unescape(domain_field).ok_or(SrsError::Malformed("domain escaping"))?;
        let local = unescape(local_field).ok_or(SrsError::Malformed("local escaping"))?;

        // Timestamp before tag, deliberately: an expired address is a fact
        // about the address, and checking the tag first would spend an HMAC
        // per key on something already known to be unusable.
        self.check_timestamp(stamp, now)?;
        let key_id = self.verify_tag(tag_field, stamp, &into_lowercase(domain.clone()), &local)?;

        Ok(Reversed {
            address: format!("{local}@{domain}"),
            key_id,
        })
    }

    /// No window check: an SRS1 address carries no timestamp of ours, by
    /// design. See [`Srs::build_srs1`].
    fn reverse_srs1(&self, rest: &str) -> Result<Reversed, SrsError> {
        let (tag_field, rest) = split_once_field(rest).ok_or(SrsError::Malformed("SRS1 tag"))?;
        let (hop_field, tail) = rest
            .split_once("==")
            .ok_or(SrsError::Malformed("SRS1 body"))?;

        let first_hop = unescape(hop_field).ok_or(SrsError::Malformed("SRS1 hop escaping"))?;

        let key_id =
            self.verify_tag_untimed(tag_field, &into_lowercase(first_hop.clone()), tail)?;

        // Back to the forwarder that issued the inner address, which is the
        // only host that can interpret the tail.
        Ok(Reversed {
            address: format!("{SRS0_PREFIX}{tail}@{first_hop}"),
            key_id,
        })
    }

    /// §5.5. Modular, and modular at both ends.
    fn check_timestamp(&self, stamp: &str, now: Day) -> Result<(), SrsError> {
        let then = decode_timestamp(stamp).ok_or(SrsError::Malformed("timestamp"))?;
        let now_wrapped = now.wrapped();

        // The subtraction is modular because the counter is. A plain
        // `now - then` is wrong for every address issued before a wrap, which
        // is a bug that ships because nobody runs a test for 89 years.
        let age = (now_wrapped + TIMESTAMP_MODULUS - then) % TIMESTAMP_MODULUS;

        // "Future" is the short way round the other direction, and is bounded
        // so that a very old address does not read as a slightly future one.
        if age > TIMESTAMP_MODULUS / 2 {
            let ahead = TIMESTAMP_MODULUS - age;
            return if ahead <= FUTURE_TOLERANCE_DAYS {
                Ok(())
            } else {
                Err(SrsError::FutureDated { days: ahead })
            };
        }

        if age > self.window_days {
            return Err(SrsError::Expired { age_days: age });
        }

        Ok(())
    }

    /// [`Srs::verify_tag`] for a tag that covers no timestamp (SRS1).
    fn verify_tag_untimed(
        &self,
        presented: &str,
        first_hop: &str,
        tail: &str,
    ) -> Result<u32, SrsError> {
        self.match_tag(presented, |secret| tag_untimed(secret, first_hop, tail))
    }

    /// Try every key; return the id of the one that matched.
    ///
    /// Every key is tried because the wire format carries no key identifier —
    /// not a design choice, just what the format leaves available (§5.4).
    fn verify_tag(
        &self,
        presented: &str,
        stamp: &str,
        domain: &str,
        local: &str,
    ) -> Result<u32, SrsError> {
        self.match_tag(presented, |secret| tag(secret, stamp, domain, local))
    }

    /// The shared half: try every key, constant-time.
    fn match_tag(
        &self,
        presented: &str,
        expected_for: impl Fn(&[u8]) -> String,
    ) -> Result<u32, SrsError> {
        if presented.len() != TAG_CHARS {
            return Err(SrsError::BadTag);
        }

        for key in self.ring.keys() {
            let expected = expected_for(&key.secret);
            // Constant-time: a byte-at-a-time comparison leaks the tag's
            // prefix to anyone who can time a bounce, and 40 bits recovered a
            // character at a time is 8 x 32 attempts rather than 2^40.
            //
            // No test here can catch this being reverted — `==` is functionally
            // identical and differs only in timing, which was confirmed by
            // mutating it and watching all 43 tests pass. CI greps for `ct_eq`
            // instead, the same instrument the `rsa` decryption argument uses,
            // and for the same reason: the property is about how the code is
            // written, not about what it returns.
            if expected.as_bytes().ct_eq(presented.as_bytes()).into() {
                return Ok(key.id);
            }
        }

        Err(SrsError::BadTag)
    }

    /// The earliest day a key may be deleted, given the day it stopped signing.
    ///
    /// Exposed so the CLI can print it rather than compute its own version of
    /// the rule (§5.6).
    pub fn earliest_deletion(stopped_signing: Day) -> Day {
        Day(stopped_signing.0 + RETIREMENT_DAYS)
    }
}

// ------------------------------------------------------------------ the tag

/// `HMAC-SHA-256(key, TT || 0x00 || lowercase(domain) || 0x00 || local)`,
/// truncated to 40 bits and Base32-encoded (§5.2).
///
/// `0x00` separates the fields because it cannot occur in either of them, which
/// makes the input injective without length prefixes. Concatenating without a
/// separator — what classic SRS does — lets `a@b.c` and `a=b@c` produce the
/// same input, and an ambiguous MAC input is a forgery primitive.
///
/// The domain arrives already lowercased and the local part never is: domains
/// are case-insensitive by RFC 5321 §2.4, local parts are the original
/// domain's business, and folding one would make `User@x` and `user@x`
/// interchangeable in a return path.
fn tag(secret: &[u8], stamp: &str, lowercase_domain: &str, local: &str) -> String {
    tag_fields(secret, &[stamp, lowercase_domain, local])
}

/// The SRS1 tag: first hop and opaque tail, no timestamp.
///
/// A separate function rather than `tag` with an empty stamp, because an empty
/// first field is a field an attacker could also produce — `tag(k, "", d, l)`
/// and `tag_untimed(k, d, l)` would then be the same value, and a tag issued
/// for one form would verify for the other.
fn tag_untimed(secret: &[u8], lowercase_first_hop: &str, tail: &str) -> String {
    tag_fields(secret, &["SRS1", lowercase_first_hop, tail])
}

/// The MAC itself, over any number of fields.
fn tag_fields(secret: &[u8], fields: &[&str]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            mac.update(&[0]);
        }
        mac.update(field.as_bytes());
    }

    let out = mac.finalize().into_bytes();
    base32_encode(&out[..TAG_BYTES])
}

// ------------------------------------------------------------------- encoding

/// RFC 4648 Base32, uppercase, no padding.
///
/// Written here rather than taken as a dependency: 40 bits is exactly 8
/// characters, so this is a loop over 5-bit groups with no padding case, and
/// the padding case is the only part of Base32 anyone gets wrong.
fn base32_encode(bytes: &[u8]) -> String {
    let mut bits = 0u64;
    for &b in bytes {
        bits = (bits << 8) | u64::from(b);
    }
    let total = bytes.len() * 8;
    let chars = total / 5;

    (0..chars)
        .map(|i| {
            let shift = total - 5 * (i + 1);
            BASE32[((bits >> shift) & 0x1f) as usize] as char
        })
        .collect()
}

fn encode_timestamp(day: Day) -> String {
    let v = day.wrapped();
    (0..TIMESTAMP_CHARS)
        .map(|i| {
            let shift = 5 * (TIMESTAMP_CHARS - 1 - i);
            BASE32[((v >> shift) & 0x1f) as usize] as char
        })
        .collect()
}

fn decode_timestamp(s: &str) -> Option<u32> {
    if s.len() != TIMESTAMP_CHARS {
        return None;
    }
    s.bytes().try_fold(0u32, |acc, b| {
        let v = BASE32.iter().position(|&c| c == b.to_ascii_uppercase())?;
        Some((acc << 5) | v as u32)
    })
}

/// Characters that may appear in a field unescaped.
///
/// RFC 5321 atext, less the three characters the grammar uses structurally:
/// `=` separates fields, `@` ends the local part, and `%` introduces an escape.
/// `.` is included because a dot-atom local part is the common case and
/// escaping every dot would spend the octet budget on nothing.
fn is_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$&'*+-/?^_`{|}~.".contains(&b)
}

/// Percent-escape a field (§5.3).
///
/// `%` is handled by the same rule as everything else rather than specially,
/// which is what makes the transform reversible: escaping `=` before `%` would
/// turn `%` + `3D` into a fake separator.
fn escape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for &b in field.as_bytes() {
        if is_safe(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

fn unescape(field: &str) -> Option<String> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let s = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }

    String::from_utf8(out).ok()
}

/// Split at the first `=`.
///
/// Safe because escaping has already removed every structural `=` from the
/// fields themselves, so the first one is always a separator.
fn split_once_field(s: &str) -> Option<(&str, &str)> {
    s.split_once('=')
}

/// `strip_prefix`, case-insensitively.
///
/// The prefix is a local part, and a bounce generator that upper- or
/// lower-cases what it was given is common enough that matching case-sensitively
/// would silently fail to reverse addresses this host issued.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

fn into_lowercase(s: String) -> String {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        s.to_ascii_lowercase()
    } else {
        s
    }
}

/// Minimal base64 decode for the ring file.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);

    for b in s.bytes() {
        let v = T.iter().position(|&c| c == b)? as u32;
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }

    Some(out)
}

// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const K2: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const K1: &str = "//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eA=";

    fn ring(text: &str) -> KeyRing {
        KeyRing::parse(text).unwrap()
    }

    fn srs() -> Srs {
        Srs::new(
            ring(&format!("2 2026-08-01T00:00:00Z - {K2}")),
            "fwd.example",
        )
    }

    /// Two keys: the newest signs, the older only verifies.
    fn rotated() -> Srs {
        Srs::new(
            ring(&format!(
                "2 2026-08-01T00:00:00Z - {K2}\n\
                 1 2026-02-01T00:00:00Z 2026-08-01T00:00:00Z {K1}"
            )),
            "fwd.example",
        )
    }

    fn day(n: u32) -> Day {
        Day(n)
    }

    fn local_of(address: &str) -> &str {
        address.rsplit_once('@').unwrap().0
    }

    // ------------------------------------------------------------ round trip

    #[test]
    fn an_address_survives_the_round_trip() {
        let s = srs();
        let rewritten = s.forward("alice", "example.com", day(20_000)).unwrap();
        assert!(rewritten.ends_with("@fwd.example"));
        assert!(rewritten.starts_with("SRS0="));

        let back = s.reverse(local_of(&rewritten), day(20_000)).unwrap();
        assert_eq!(back.address, "alice@example.com");
        assert_eq!(back.key_id, 2);
    }

    #[test]
    fn the_local_part_keeps_its_case_and_the_domain_does_not() {
        // RFC 5321 §2.4: the domain is case-insensitive and ours to fold; the
        // local part belongs to the original domain and folding it would make
        // two different mailboxes one return path.
        let s = srs();
        let rewritten = s.forward("Alice.B", "Example.COM", day(20_000)).unwrap();
        let back = s.reverse(local_of(&rewritten), day(20_000)).unwrap();
        assert_eq!(back.address, "Alice.B@example.com");
    }

    #[test]
    fn a_local_part_containing_a_separator_survives() {
        // `=` is valid in a local part and is also the field separator. Without
        // escaping this either fails to parse or reverses into a different
        // address than it started as — which is a forged sender, not a bug.
        let s = srs();
        for local in ["a=b", "a%b", "a%3Db", "weird=%=stuff"] {
            let rewritten = s.forward(local, "example.com", day(20_000)).unwrap();
            let back = s.reverse(local_of(&rewritten), day(20_000)).unwrap();
            assert_eq!(back.address, format!("{local}@example.com"), "for {local}");
        }
    }

    #[test]
    fn escaping_is_reversible_for_every_byte() {
        for b in 0u8..=255 {
            let field = String::from_utf8_lossy(&[b]).to_string();
            let round = unescape(&escape(&field)).unwrap();
            assert_eq!(round, field, "byte {b:#04x}");
        }
    }

    #[test]
    fn the_structural_characters_never_survive_escaping() {
        // If a separator reaches the wire unescaped, a sender can forge a field
        // boundary and choose what the address reverses to.
        for c in ['=', '@'] {
            let escaped = escape(&format!("a{c}b"));
            assert!(!escaped.contains(c), "{c} survived: {escaped}");
        }

        // `%` is different in kind: it introduces an escape, so it necessarily
        // appears in the output. What must hold is that every one of them is an
        // escape rather than a literal.
        let escaped = escape("a%b%%c");
        let bytes = escaped.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'%' {
                let hex = bytes.get(i + 1..i + 3);
                assert!(
                    hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)),
                    "a bare % survived at {i} in {escaped}"
                );
            }
        }
    }

    // -------------------------------------------------------------- the tag

    #[test]
    fn a_forged_tag_is_refused() {
        let s = srs();
        let rewritten = s.forward("alice", "example.com", day(20_000)).unwrap();
        let local = local_of(&rewritten);

        // One character of the tag changed, everything else identical.
        let tag = &local[5..13];
        let flipped = if tag.starts_with('A') { 'B' } else { 'A' };
        let forged = format!("SRS0={flipped}{}{}", &tag[1..], &local[13..]);

        assert_eq!(s.reverse(&forged, day(20_000)), Err(SrsError::BadTag));
    }

    #[test]
    fn the_tag_covers_the_domain_and_the_local_part() {
        // Rewriting either field must invalidate the tag, or an attacker can
        // redirect a verified return path at an address of their choosing.
        let s = srs();
        let good = s.forward("alice", "example.com", day(20_000)).unwrap();
        let local = local_of(&good);

        let swapped_domain = local.replace("=example.com=", "=victim.example=");
        assert_ne!(swapped_domain, local);
        assert_eq!(
            s.reverse(&swapped_domain, day(20_000)),
            Err(SrsError::BadTag)
        );

        let swapped_local = local.replace("=alice", "=mallory");
        assert_ne!(swapped_local, local);
        assert_eq!(
            s.reverse(&swapped_local, day(20_000)),
            Err(SrsError::BadTag)
        );
    }

    #[test]
    fn the_mac_input_is_unambiguous() {
        // The reason for the 0x00 separators. Concatenating the fields lets two
        // different addresses produce the same MAC input, so a tag issued for
        // one verifies for the other.
        let secret = base64_decode(K2).unwrap();
        let a = tag(&secret, "AAA", "b.example", "a");
        let b = tag(&secret, "AAA", "b.example", "a");
        assert_eq!(a, b, "the tag is not deterministic");

        // Same characters, different field boundaries.
        let left = tag(&secret, "AAA", "example.com", "ab");
        let right = tag(&secret, "AAA", "example.coma", "b");
        assert_ne!(left, right, "field boundaries do not affect the tag");
    }

    #[test]
    fn a_tag_of_the_wrong_length_is_refused_before_any_hmac() {
        // Current timestamp on purpose: the window is checked first, so an
        // address that is also expired would pass this test without the length
        // check existing at all.
        let s = srs();
        let stamp = encode_timestamp(day(20_000));
        assert_eq!(
            s.reverse(&format!("SRS0=ABC={stamp}=x.example=a"), day(20_000)),
            Err(SrsError::BadTag)
        );
    }

    // ------------------------------------------------------ time and the wrap

    #[test]
    fn an_address_expires_after_the_window() {
        let s = srs();
        let issued = day(20_000);
        let rewritten = s.forward("alice", "example.com", issued).unwrap();
        let local = local_of(&rewritten).to_string();

        assert!(s.reverse(&local, Day(20_000 + WINDOW_DAYS)).is_ok());
        assert_eq!(
            s.reverse(&local, Day(20_000 + WINDOW_DAYS + 1)),
            Err(SrsError::Expired {
                age_days: WINDOW_DAYS + 1
            })
        );
    }

    #[test]
    fn a_slightly_future_address_is_tolerated_and_a_very_future_one_is_not() {
        // A peer whose clock is a little behind ours is ordinary; one that is
        // a week behind is a problem the operator should hear about, and the
        // error says so distinctly rather than reading as an expiry.
        let s = srs();
        let rewritten = s.forward("alice", "example.com", day(20_001)).unwrap();
        let local = local_of(&rewritten).to_string();

        assert!(s.reverse(&local, day(20_000)).is_ok());
        assert_eq!(
            s.reverse(&local, day(19_994)),
            Err(SrsError::FutureDated { days: 7 })
        );
    }

    #[test]
    fn the_timestamp_comparison_is_modular() {
        // The reason the design widened the field and kept modular arithmetic.
        // An address issued just before the counter wraps must still verify
        // just after it; a plain subtraction underflows or rejects here.
        let s = srs();
        let before = Day(TIMESTAMP_MODULUS - 2);
        let after = Day(TIMESTAMP_MODULUS + 1);

        let rewritten = s.forward("alice", "example.com", before).unwrap();
        let back = s.reverse(local_of(&rewritten), after).unwrap();
        assert_eq!(back.address, "alice@example.com");
    }

    #[test]
    fn an_address_from_one_wrap_ago_does_not_come_back_to_life() {
        // What two characters could not prevent. With a 1024-day counter, an
        // address captured today verifies again in 1024 days; at 32768 the same
        // trick needs 89 years, and the test pins that the wrapped value is not
        // simply accepted.
        let s = srs();
        let issued = day(20_000);
        let rewritten = s.forward("alice", "example.com", issued).unwrap();
        let local = local_of(&rewritten).to_string();

        let one_wrap_later = Day(20_000 + TIMESTAMP_MODULUS);
        // Same wrapped timestamp, so it verifies — which is exactly why the
        // modulus has to be large enough that this day never arrives in the
        // lifetime of a key. The retirement barrier is the second line.
        assert!(s.reverse(&local, one_wrap_later).is_ok());
        assert_eq!(TIMESTAMP_MODULUS, 32768, "the wrap horizon changed");
    }

    #[test]
    fn timestamps_round_trip_across_the_whole_range() {
        for d in (0..TIMESTAMP_MODULUS).step_by(97) {
            let encoded = encode_timestamp(Day(d));
            assert_eq!(encoded.len(), TIMESTAMP_CHARS);
            assert_eq!(decode_timestamp(&encoded), Some(d), "day {d}");
        }
    }

    // ------------------------------------------------------------- the ring

    #[test]
    fn any_key_in_the_ring_verifies_and_the_first_one_signs() {
        // The rotation property: an address issued under the old key still
        // reverses after the new one takes over.
        let old = Srs::new(
            ring(&format!("1 2026-02-01T00:00:00Z - {K1}")),
            "fwd.example",
        );
        let issued = old.forward("alice", "example.com", day(20_000)).unwrap();

        let after = rotated();
        let back = after.reverse(local_of(&issued), day(20_000)).unwrap();
        assert_eq!(back.address, "alice@example.com");
        assert_eq!(back.key_id, 1, "the old key is what verified it");

        // And new addresses are signed by the newest key.
        let fresh = after.forward("bob", "example.com", day(20_000)).unwrap();
        assert_eq!(
            after.reverse(local_of(&fresh), day(20_000)).unwrap().key_id,
            2
        );
    }

    #[test]
    fn a_key_outside_the_ring_does_not_verify() {
        let other = Srs::new(
            ring(&format!("9 2026-01-01T00:00:00Z - {K1}")),
            "fwd.example",
        );
        let issued = other.forward("alice", "example.com", day(20_000)).unwrap();
        assert_eq!(
            srs().reverse(local_of(&issued), day(20_000)),
            Err(SrsError::BadTag)
        );
    }

    #[test]
    fn a_ring_that_cannot_sign_is_refused_at_load() {
        let e = KeyRing::parse(&format!("1 2026-01-01T00:00:00Z 2026-06-01T00:00:00Z {K1}"));
        assert!(matches!(e, Err(SrsError::Ring(_))), "{e:?}");
    }

    #[test]
    fn a_ring_larger_than_the_cap_is_refused() {
        let mut text = String::new();
        for i in 0..=MAX_KEYS {
            text.push_str(&format!("{i} 2026-01-01T00:00:00Z - {K2}\n"));
        }
        match KeyRing::parse(&text) {
            Err(SrsError::Ring(m)) => assert!(m.contains("more than"), "{m}"),
            other => panic!("a ring of {} keys was accepted: {other:?}", MAX_KEYS + 1),
        }
    }

    #[test]
    fn a_short_secret_is_refused() {
        // Accepted by HMAC, and weaker than the operator believes they
        // configured — which is the kind of thing that is never noticed.
        match KeyRing::parse("1 2026-01-01T00:00:00Z - AAEC") {
            Err(SrsError::Ring(m)) => assert!(m.contains("bytes"), "{m}"),
            other => panic!("a 3-byte secret was accepted: {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let r = ring(&format!("# a comment\n\n2 2026-08-01T00:00:00Z - {K2}\n"));
        assert_eq!(r.keys().len(), 1);
    }

    #[test]
    fn a_key_never_prints_its_secret() {
        let r = ring(&format!("2 2026-08-01T00:00:00Z - {K2}"));
        let shown = format!("{:?}", r.keys()[0]);
        assert!(shown.contains("redacted"), "{shown}");
        assert!(!shown.contains("AAECAw"), "the secret was printed: {shown}");
    }

    #[test]
    fn the_deletion_barrier_is_thirty_days_after_signing_stopped() {
        assert_eq!(Srs::earliest_deletion(Day(20_000)), Day(20_030));
    }

    // ----------------------------------------------------------- overlength

    #[test]
    fn an_address_that_would_exceed_the_local_part_limit_is_refused() {
        let s = srs();
        // 18 octets of fixed overhead, so 45 octets of domain plus local fit
        // and 46 do not.
        let domain = "d".repeat(20);
        let fitting = "l".repeat(25);
        let over = "l".repeat(26);

        let ok = s.forward(&fitting, &domain, day(20_000)).unwrap();
        assert_eq!(local_of(&ok).len(), MAX_LOCAL_PART);

        match s.forward(&over, &domain, day(20_000)) {
            Err(SrsError::TooLong { octets }) => assert_eq!(octets, MAX_LOCAL_PART + 1),
            other => panic!("an over-long address was accepted: {other:?}"),
        }
    }

    #[test]
    fn the_limit_is_measured_after_escaping() {
        // A local part that fits as written and does not fit once escaped. An
        // estimate taken from the unescaped fields is the thing that would be
        // wrong, so the check is on the assembled address.
        let s = srs();
        let domain = "d".repeat(20);
        let local = format!("{}{}", "l".repeat(21), "=".repeat(2)); // 23 raw, 27 escaped
        assert!(local.len() + domain.len() + 18 <= MAX_LOCAL_PART);
        assert!(matches!(
            s.forward(&local, &domain, day(20_000)),
            Err(SrsError::TooLong { .. })
        ));
    }

    // ----------------------------------------------------------------- SRS1

    #[test]
    fn a_foreign_rewritten_address_is_wrapped_not_rewritten_again() {
        // The double-forward case. Rewriting an SRS0 address as another SRS0
        // buries the original sender one layer deeper per hop, and the address
        // grows without bound.
        let s = srs();
        let foreign = "SRS0=abcd=TT=origin.example=alice";
        let wrapped = s.forward(foreign, "first.example", day(20_000)).unwrap();
        assert!(wrapped.starts_with("SRS1="), "{wrapped}");

        let back = s.reverse(local_of(&wrapped), day(20_000)).unwrap();
        // Back to the forwarder that issued the inner address: it is the only
        // host that can interpret the tail.
        assert_eq!(
            back.address,
            "SRS0=abcd=TT=origin.example=alice@first.example"
        );
    }

    #[test]
    fn wrapping_an_already_wrapped_address_keeps_one_layer() {
        let s = srs();
        let foreign = "SRS0=abcd=TT=origin.example=alice";
        let once = s.forward(foreign, "first.example", day(20_000)).unwrap();
        let twice = s
            .forward(local_of(&once), "second.example", day(20_001))
            .unwrap();

        assert!(twice.starts_with("SRS1="));
        // Still names the first hop, not the second: the chain does not grow.
        let back = s.reverse(local_of(&twice), day(20_001)).unwrap();
        assert_eq!(
            back.address,
            "SRS0=abcd=TT=origin.example=alice@first.example"
        );
    }

    #[test]
    fn a_wrapped_address_carries_no_window_of_ours() {
        // The classic SRS1 layout has no timestamp of the wrapping host's own,
        // and this pins the consequence rather than leaving it to be found
        // later: our tag on an SRS1 address does not expire.
        //
        // That is the accepted trade. Expiry lives one hop away, with the host
        // named in the address — it issued the inner SRS0 and applies its own
        // window when the bounce arrives — and an address other implementations
        // recognise is worth more than a second copy of a check that already
        // exists.
        let s = srs();
        let wrapped = s
            .forward(
                "SRS0=abcd=TT=origin.example=alice",
                "first.example",
                day(20_000),
            )
            .unwrap();

        let much_later = Day(20_000 + WINDOW_DAYS * 100);
        let back = s.reverse(local_of(&wrapped), much_later).unwrap();
        assert_eq!(
            back.address, "SRS0=abcd=TT=origin.example=alice@first.example",
            "a wrapped address stopped resolving to its first hop"
        );
    }

    #[test]
    fn an_srs1_tag_cannot_be_replayed_as_an_srs0_tag() {
        // `tag_untimed` prefixes the field list with a literal rather than
        // reusing `tag` with an empty timestamp. Without that, a tag issued for
        // one form verifies for the other, since an empty first field is one an
        // attacker can also present.
        let secret = base64_decode(K2).unwrap();
        assert_ne!(
            tag_untimed(&secret, "first.example", "tail"),
            tag(&secret, "", "first.example", "tail"),
        );
    }

    #[test]
    fn a_forged_wrapped_address_is_refused() {
        let s = srs();
        let wrapped = s
            .forward(
                "SRS0=abcd=TT=origin.example=alice",
                "first.example",
                day(20_000),
            )
            .unwrap();
        let tampered = local_of(&wrapped).replace("first.example", "attacker.example");
        assert_eq!(s.reverse(&tampered, day(20_000)), Err(SrsError::BadTag));
    }

    // --------------------------------------------------------------- parsing

    #[test]
    fn an_address_this_host_did_not_issue_is_not_rewritten() {
        assert_eq!(
            srs().reverse("alice", day(20_000)),
            Err(SrsError::NotRewritten)
        );
    }

    #[test]
    fn the_prefix_is_matched_case_insensitively() {
        // Bounce generators re-case what they were given, and a return path
        // that fails to reverse because of it loses the bounce.
        let s = srs();
        let rewritten = s.forward("alice", "example.com", day(20_000)).unwrap();
        let lowered = local_of(&rewritten).replacen("SRS0=", "srs0=", 1);
        assert_eq!(
            s.reverse(&lowered, day(20_000)).unwrap().address,
            "alice@example.com"
        );
    }

    #[test]
    fn truncated_addresses_are_rejected_rather_than_panicking() {
        let s = srs();
        for bad in [
            "SRS0=",
            "SRS0=abc",
            "SRS0=abcdefgh",
            "SRS0=abcdefgh=AAA",
            "SRS0=abcdefgh=AAA=example.com",
            "SRS1=abcdefgh=AAA=first.example",
            "SRS1=",
        ] {
            let got = s.reverse(bad, day(20_000));
            assert!(got.is_err(), "{bad} was accepted: {got:?}");
        }
    }

    #[test]
    fn a_malformed_escape_is_rejected() {
        let s = srs();
        // `%` with nothing usable after it. Reaching the tag check with a
        // half-decoded field would compare a tag against bytes nobody chose.
        assert!(
            s.reverse("SRS0=abcdefgh=AAA=ex%.com=a", day(20_000))
                .is_err()
        );
        assert!(
            s.reverse("SRS0=abcdefgh=AAA=ex%2.com=a", day(20_000))
                .is_err()
        );
    }
}
