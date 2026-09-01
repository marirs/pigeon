//! DKIM keypairs: generating them, rendering the record, and proving that the
//! key on disk is the one published in DNS.
//!
//! # Only generation lives here
//!
//! `rsa` is in this workspace for one reason — `ring` cannot generate RSA keys,
//! and every other option is a TLS backend `deny.toml` bans. Signing arrives in
//! Milestone 2 and must use `ring`.
//!
//! That is not a style preference. `deny.toml` carries an exception for
//! RUSTSEC-2023-0071, and the exception's whole argument is that Pigeon never
//! performs an RSA operation on attacker-supplied input. Generation takes no
//! input at all. Signing takes a hash of a message somebody else wrote, so it
//! is a different argument that has not been made.
//!
//! CI greps for decryption calls, so the exception is checked rather than
//! asserted.
//!
//! # The key is the one thing no backup of the database restores
//!
//! A DKIM private key cannot be regenerated: losing it means republishing DNS
//! for every domain by hand. It lives on disk at `0600`, never in SQLite, and
//! never in any output.

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroizing;

/// The selector Pigeon publishes under unless told otherwise.
///
/// Appears in DNS as `pigeon._domainkey.example.com`.
pub const DEFAULT_SELECTOR: &str = "pigeon";

/// RSA-2048 is the default, and Ed25519 is not an alternative to it.
///
/// Ed25519 remains unevenly supported by receivers, so it is offered only as an
/// *additional* selector alongside RSA, never alone — a domain publishing only
/// an Ed25519 key is a domain whose mail fails DKIM at anything that has not
/// implemented RFC 8463.
pub const DEFAULT_BITS: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum DkimError {
    #[error("could not generate a {bits}-bit RSA key: {source}")]
    Generate {
        bits: usize,
        #[source]
        source: rsa::Error,
    },

    #[error("could not encode the private key: {0}")]
    EncodePrivate(#[from] rsa::pkcs8::Error),

    #[error("could not encode the public key: {0}")]
    EncodePublic(#[from] rsa::pkcs8::spki::Error),

    /// Ed25519 generation, which goes through `ring` rather than `rsa` and so
    /// carries a message rather than a typed source.
    #[error("could not generate an ed25519 key: {0}")]
    GenerateEd25519(String),

    #[error("{path} is not a usable PKCS#8 private key: {source}")]
    ReadPrivate {
        path: String,
        #[source]
        source: rsa::pkcs8::Error,
    },

    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "the DKIM key recorded as {recorded} is {actual} bits, not {expected}.\n\n  \
         The record published in DNS advertises a key of a different strength than the \
         one signing with it. Generate a new key of the recorded type, or correct the \
         record."
    )]
    WrongKeySize {
        recorded: String,
        expected: usize,
        actual: usize,
    },

    #[error(
        "DKIM algorithm {algorithm} is recorded but not implemented. Ed25519 is a \
         Milestone 5 item, and is only ever an additional selector alongside RSA — a \
         domain publishing it alone fails DKIM at every receiver that has not \
         implemented RFC 8463."
    )]
    AlgorithmNotImplemented { algorithm: String },

    #[error("DKIM algorithm {algorithm:?} is not one this build recognises")]
    UnknownAlgorithm { algorithm: String },

    #[error(
        "the private key at {path} does not match the public key published for \
         {selector}._domainkey.{domain}.\n\n  \
         Every signature this key makes would verify as dkim=fail, at the receiver, \
         silently.\n\n  \
         Either restore the matching private key, or generate a new one and publish \
         its record."
    )]
    Mismatch {
        path: String,
        domain: String,
        selector: String,
    },
}

/// A freshly generated keypair.
///
/// The private half is PKCS#8 PEM, ready to write to disk. The public half is
/// the base64 that goes in the `p=` tag.
///
/// # Not `Debug`-derived, and not `Clone`
///
/// A derived `Debug` prints every field, so `{:?}` on this — in a log line, an
/// error, a panic message, a test failure — would have written the complete
/// private key wherever that went. `SECURITY.md` says DKIM private keys are
/// never logged; a derive is how that stops being true without anybody
/// deciding it.
///
/// `Clone` is absent for a duller reason: every copy is another buffer to
/// wipe, and there is no use for a second one.
pub struct KeyPair {
    /// `Zeroizing`, so the buffer is wiped when it drops.
    ///
    /// `to_pkcs8_pem` already returns one; the earlier version called
    /// `.to_string()` on it, which copied the key into an ordinary `String`
    /// that is freed without being cleared and leaves the material in whatever
    /// the allocator hands out next.
    private_pem: Zeroizing<String>,
    public_base64: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("private_pem", &"<redacted>")
            .field("public_base64", &self.public_base64)
            .finish()
    }
}

impl KeyPair {
    /// Generate an RSA keypair.
    ///
    /// Slow — a second or two for 2048 bits — and that is fine: it happens once
    /// per domain, in `pigeon domain add`, in front of a person who just typed
    /// a command.
    pub fn generate(bits: usize) -> Result<Self, DkimError> {
        let mut rng = rsa::rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|source| DkimError::Generate { bits, source })?;
        Self::from_private(private)
    }

    fn from_private(private: RsaPrivateKey) -> Result<Self, DkimError> {
        let public = RsaPublicKey::from(&private);
        Ok(Self {
            private_pem: private.to_pkcs8_pem(LineEnding::LF)?,
            public_base64: spki_base64(&public)?,
        })
    }

    /// PKCS#8 PEM. Write it `0600` and never print it.
    ///
    /// Borrowed rather than returned by value so a caller cannot casually take
    /// ownership of a copy that nothing wipes.
    pub fn private_pem(&self) -> &str {
        &self.private_pem
    }

    /// The key size, for recording alongside the public half.
    pub fn bits(&self) -> usize {
        // Parsed back rather than remembered: this is the number a verifier
        // will compute from the key on disk, so it is the one worth reporting.
        RsaPrivateKey::from_pkcs8_pem(&self.private_pem)
            .map(|k| k.n().bits())
            .unwrap_or(0)
    }

    /// The base64 for the `p=` tag, and what is stored in `dkim_key.public_key`.
    pub fn public_base64(&self) -> &str {
        &self.public_base64
    }

    /// The TXT record to publish.
    pub fn txt_record(&self) -> String {
        txt_record(&self.public_base64)
    }
}

/// Render the DKIM TXT record for a public key.
///
/// `k=rsa` is stated rather than left to default. RFC 6376 §3.6.1 makes `rsa`
/// the default for `k=`, but a resolver or a provider's UI that normalises the
/// record is one fewer thing to have to reason about when it is explicit.
pub fn txt_record(public_base64: &str) -> String {
    format!("v=DKIM1; k=rsa; p={public_base64}")
}

/// The DNS name a selector is published at.
/// An Ed25519 signing key, for the optional second selector.
///
/// Offered *alongside* RSA and never instead of it: Ed25519 support among
/// receivers is still uneven, and a message signed only with a key the receiver
/// cannot verify has no usable signature at all. Publishing both costs one
/// extra DNS record and one extra header.
///
/// Generated through `mail-auth`'s `ring` backend, like everything else that
/// touches key material here — the `rsa` crate's advisory exception rests on it
/// being used only to generate RSA keys, and this is not one.
pub struct Ed25519Pair {
    /// PKCS#8 DER, as `ring` produces it. Not PEM: `mail-auth` takes DER
    /// directly, and wrapping it would be encoding a thing to decode it again.
    pkcs8: Vec<u8>,
    public_base64: String,
}

impl Ed25519Pair {
    pub fn generate() -> Result<Self, DkimError> {
        use mail_auth::common::crypto::Ed25519Key;

        let pkcs8 =
            Ed25519Key::generate_pkcs8().map_err(|e| DkimError::GenerateEd25519(e.to_string()))?;

        // The public half is read back from the parsed key rather than sliced
        // out of the DER: the offset is an encoding detail, and a wrong slice
        // publishes a record that verifies nothing.
        let key = Ed25519Key::from_pkcs8_der(&pkcs8)
            .map_err(|e| DkimError::GenerateEd25519(e.to_string()))?;

        Ok(Self {
            // Raw 32 bytes, base64'd. Unlike RSA, an Ed25519 `p=` is the key
            // itself rather than a SubjectPublicKeyInfo wrapper (RFC 8463 §3).
            public_base64: base64_standard(&key.public_key()),
            pkcs8,
        })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn public_base64(&self) -> &str {
        &self.public_base64
    }

    /// The record to publish. `k=ed25519`, which is what tells a receiver which
    /// algorithm the `p=` value is for.
    pub fn txt_record(&self) -> String {
        format!("v=DKIM1; k=ed25519; p={}", self.public_base64)
    }
}

pub fn record_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

/// What `dkim_key.algorithm` records, and what it implies about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Rsa2048,
    Ed25519,
}

impl Algorithm {
    pub fn from_stored(raw: &str) -> Option<Self> {
        match raw {
            "rsa2048" => Some(Self::Rsa2048),
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// What a private key on disk actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyShape {
    pub bits: usize,
}

/// Read a private key and report the public half *and* the key's shape.
///
/// The shape matters because the database records an algorithm and the earlier
/// check ignored it: a 1024-bit key recorded as `rsa2048` matched its own
/// public half perfectly and started the daemon. The record published in DNS
/// would then advertise a key half the strength of what the configuration
/// claims, and nothing would say so.
pub fn inspect_private_file(path: &std::path::Path) -> Result<(String, KeyShape), DkimError> {
    // Zeroized on drop. The earlier version read the key into a plain `String`
    // that was freed without being cleared.
    let pem = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|source| DkimError::Io {
            path: path.display().to_string(),
            source,
        })?,
    );

    let private = RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|source| DkimError::ReadPrivate {
        path: path.display().to_string(),
        source,
    })?;

    let public = RsaPublicKey::from(&private);
    Ok((
        spki_base64(&public)?,
        KeyShape {
            bits: public.n().bits(),
        },
    ))
}

/// Check a key's shape against the algorithm recorded for it.
pub fn check_algorithm(recorded: &str, shape: KeyShape) -> Result<(), DkimError> {
    match Algorithm::from_stored(recorded) {
        Some(Algorithm::Rsa2048) => {
            if shape.bits != 2048 {
                return Err(DkimError::WrongKeySize {
                    recorded: recorded.to_string(),
                    expected: 2048,
                    actual: shape.bits,
                });
            }
            Ok(())
        }
        // Refused rather than skipped. An Ed25519 row would reach the RSA
        // parser above and fail with a confusing message about PKCS#8; saying
        // it is not implemented is the honest version, and it is on the
        // Milestone 5 list.
        Some(Algorithm::Ed25519) => Err(DkimError::AlgorithmNotImplemented {
            algorithm: "ed25519".to_string(),
        }),
        None => Err(DkimError::UnknownAlgorithm {
            algorithm: recorded.to_string(),
        }),
    }
}

/// Derive the public key from a private key on disk, as base64.
///
/// This is what makes the startup check a check. An existence test passes for a
/// key file replaced during a botched rotation, or restored from a backup taken
/// before the last one — and then every message is signed with a key whose
/// public half is not the one in DNS. Every signature verifies as `dkim=fail`,
/// at the receiver, silently, while the daemon reports a clean start.
pub fn public_from_private_file(path: &std::path::Path) -> Result<String, DkimError> {
    let pem = std::fs::read_to_string(path).map_err(|source| DkimError::Io {
        path: path.display().to_string(),
        source,
    })?;
    public_from_private_pem(&pem).map_err(|e| match e {
        DkimError::EncodePrivate(source) => DkimError::ReadPrivate {
            path: path.display().to_string(),
            source,
        },
        other => other,
    })
}

/// Derive the public key from PKCS#8 PEM, as base64.
pub fn public_from_private_pem(pem: &str) -> Result<String, DkimError> {
    let private = RsaPrivateKey::from_pkcs8_pem(pem)?;
    spki_base64(&RsaPublicKey::from(&private))
}

/// SubjectPublicKeyInfo DER, base64-encoded.
///
/// Taken from the PEM rather than by adding a base64 dependency: PEM *is*
/// base64 with a header, a footer and line breaks, so removing those is the
/// whole conversion.
/// Standard base64, which is what a DKIM `p=` tag carries.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Written out rather than pulled in: this is one 32-byte value encoded
    // once at key generation, and a dependency for it would be a dependency to
    // review for ever.
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn spki_base64(public: &RsaPublicKey) -> Result<String, DkimError> {
    let pem = public.to_public_key_pem(LineEnding::LF)?;
    Ok(pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_encoding_a_receiver_expects() {
        // RFC 4648 test vectors. The encoder is written out here rather than
        // pulled in, so it is worth proving against the specification's own
        // examples instead of against itself.
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
        // A byte that exercises the top of the alphabet.
        assert_eq!(base64_standard(&[0xff, 0xef, 0xbe]), "/+++");
    }

    #[test]
    fn an_ed25519_record_names_its_algorithm() {
        // `k=ed25519` is what tells a receiver which algorithm the `p=` value
        // is for. Without it the record reads as RSA and verifies nothing.
        let pair = Ed25519Pair::generate().expect("ring generates ed25519 keys");
        let record = pair.txt_record();
        assert!(record.contains("k=ed25519"), "{record}");
        assert!(record.starts_with("v=DKIM1;"), "{record}");

        // 32 raw bytes, base64'd — not a SubjectPublicKeyInfo wrapper, which is
        // what RSA publishes and what an Ed25519 verifier would reject
        // (RFC 8463 §3).
        let p = record.split("p=").nth(1).expect("a p= tag");
        assert_eq!(p.len(), 44, "an ed25519 p= is 32 bytes base64'd: {p}");
    }

    #[test]
    fn an_ed25519_key_signs_through_the_pipeline() {
        // The pair is only useful if `mail-auth` accepts the DER back, which is
        // the half that a generation test alone does not prove.
        let pair = Ed25519Pair::generate().unwrap();
        crate::pipeline::SigningKey::from_ed25519_pkcs8(pair.pkcs8(), "example.com", "ed")
            .expect("the generated key should load");
    }

    /// 1024 bits everywhere below. Too short to publish and fast enough to run
    /// in a test suite; every property here is about encoding and matching
    /// rather than about key strength.
    const TEST_BITS: usize = 1024;

    #[test]
    fn a_generated_key_round_trips_through_its_pem() {
        let pair = KeyPair::generate(TEST_BITS).expect("generate");
        let derived = public_from_private_pem(pair.private_pem()).expect("derive");
        assert_eq!(
            derived,
            pair.public_base64(),
            "the public key derived from the private half is not the one published"
        );
    }

    #[test]
    fn two_generated_keys_are_different() {
        // A generator that returned the same key twice would pass every other
        // test in this file.
        let a = KeyPair::generate(TEST_BITS).unwrap();
        let b = KeyPair::generate(TEST_BITS).unwrap();
        assert_ne!(a.public_base64(), b.public_base64());
        assert_ne!(a.private_pem(), b.private_pem());
    }

    #[test]
    fn a_different_key_does_not_match() {
        // The case the startup check exists for: a key file replaced by one
        // that is perfectly valid and simply is not the one in DNS.
        let published = KeyPair::generate(TEST_BITS).unwrap();
        let replaced = KeyPair::generate(TEST_BITS).unwrap();
        let derived = public_from_private_pem(replaced.private_pem()).unwrap();
        assert_ne!(derived, published.public_base64());
    }

    #[test]
    fn the_private_key_is_pkcs8_and_says_so() {
        let pair = KeyPair::generate(TEST_BITS).unwrap();
        assert!(
            pair.private_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(pair.private_pem().ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn the_public_key_is_bare_base64() {
        // It goes into a TXT record, so a stray newline or header would be
        // published verbatim and every verification would fail.
        let pair = KeyPair::generate(TEST_BITS).unwrap();
        let p = pair.public_base64();
        assert!(!p.contains('\n'), "public key holds a newline");
        assert!(!p.contains("-----"), "public key holds PEM armour");
        assert!(
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
            "public key is not base64: {p}"
        );
    }

    #[test]
    fn the_record_is_the_one_receivers_expect() {
        let pair = KeyPair::generate(TEST_BITS).unwrap();
        let txt = pair.txt_record();
        assert!(txt.starts_with("v=DKIM1; k=rsa; p="));
        assert!(txt.ends_with(pair.public_base64()));
        assert_eq!(
            record_name("pigeon", "example.com"),
            "pigeon._domainkey.example.com"
        );
    }

    #[test]
    fn nonsense_is_not_read_as_a_private_key() {
        assert!(public_from_private_pem("").is_err());
        assert!(public_from_private_pem("hello").is_err());
        assert!(
            public_from_private_pem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
                .is_err()
        );
    }

    #[test]
    fn a_missing_key_file_is_an_io_error_not_a_parse_error() {
        // The two need different messages: one means restore a file, the other
        // means the file is not what it claims to be.
        let err = public_from_private_file(std::path::Path::new("/nonexistent/pigeon.key"))
            .expect_err("read a key that is not there");
        assert!(matches!(err, DkimError::Io { .. }), "{err:?}");
    }
}

#[cfg(test)]
mod redaction {
    use super::*;

    #[test]
    fn debug_never_prints_the_private_key() {
        // A derived Debug prints every field. `{:?}` in a log line, an error, a
        // panic message or a failing assertion would then have written the
        // complete private key wherever that went.
        let pair = KeyPair::generate(1024).unwrap();
        let printed = format!("{pair:?}");
        assert!(
            !printed.contains("PRIVATE KEY"),
            "Debug leaked the private key: {printed}"
        );
        assert!(printed.contains("<redacted>"), "{printed}");
        // The public half is not a secret and is useful in a log.
        assert!(printed.contains(pair.public_base64()));
    }

    #[test]
    fn a_key_reports_its_real_size() {
        assert_eq!(KeyPair::generate(1024).unwrap().bits(), 1024);
    }

    #[test]
    fn the_recorded_algorithm_is_checked_against_the_key() {
        let small = KeyShape { bits: 1024 };
        let right = KeyShape { bits: 2048 };

        assert!(check_algorithm("rsa2048", right).is_ok());
        assert!(matches!(
            check_algorithm("rsa2048", small),
            Err(DkimError::WrongKeySize { actual: 1024, .. })
        ));
        assert!(matches!(
            check_algorithm("ed25519", right),
            Err(DkimError::AlgorithmNotImplemented { .. })
        ));
        assert!(matches!(
            check_algorithm("rsa4096", right),
            Err(DkimError::UnknownAlgorithm { .. })
        ));
    }
}
