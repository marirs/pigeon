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
use rsa::{RsaPrivateKey, RsaPublicKey};

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
#[derive(Debug, Clone)]
pub struct KeyPair {
    private_pem: String,
    public_base64: String,
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
            private_pem: private.to_pkcs8_pem(LineEnding::LF)?.to_string(),
            public_base64: spki_base64(&public)?,
        })
    }

    /// PKCS#8 PEM. Write it `0600` and never print it.
    pub fn private_pem(&self) -> &str {
        &self.private_pem
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
pub fn record_name(selector: &str, domain: &str) -> String {
    format!("{selector}._domainkey.{domain}")
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
