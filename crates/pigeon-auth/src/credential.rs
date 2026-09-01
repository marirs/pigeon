//! Application credentials: generating them, hashing them, checking them.
//!
//! A principal is an *application*, not a person: a phone's mail client, a
//! backup script, a CI job. Each gets its own username and password, so one can
//! be revoked without touching the others, and so a leaked credential names the
//! thing that leaked it.
//!
//! # Argon2id, and why the parameters are here
//!
//! Passwords are stored as Argon2id hashes and never in any other form. The
//! parameters are chosen for a mail server rather than a login page: a
//! submission client authenticates on every connection, so a cost that is
//! comfortable for one login a day is one an authenticated sender pays
//! hundreds of times. 19 MiB and one pass is the OWASP-recommended low-memory
//! profile, which keeps a single verification in the tens of milliseconds.
//!
//! That cost is also the rate limit on guessing. The generated password is 128
//! bits of randomness, so guessing is hopeless on its own terms — the hash is
//! there for the case where the *database* leaks, which is exactly when the
//! attacker gets to spend time offline.
//!
//! # Constant time is the library's job, and it does it
//!
//! `PasswordHash` verification compares digests with a constant-time equality
//! inside `password-hash`. It is written down here because the natural way to
//! "improve" this code — comparing strings, or short-circuiting on a missing
//! user — reintroduces a timing oracle for usernames.

use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use argon2::{Algorithm, Argon2, Params, Version};

/// A generated credential, in the one form a person ever sees it.
///
/// The password exists in memory here and nowhere else afterwards: what is
/// stored is the hash, and an operator who loses the password issues a new
/// credential rather than recovering the old one.
#[derive(Debug)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("could not hash the password: {0}")]
    Hash(String),
    #[error("the stored password hash is not usable: {0}")]
    StoredHash(String),
}

/// The Argon2id parameters, in one place.
///
/// 19 MiB, one pass, one lane — OWASP's low-memory profile. Chosen for a
/// protocol that authenticates per connection rather than per session: a
/// submission client reconnects, and a 250 ms verification would be 250 ms
/// added to every message.
fn argon2() -> Result<Argon2<'static>, CredentialError> {
    let params =
        Params::new(19 * 1024, 1, 1, None).map_err(|e| CredentialError::Hash(e.to_string()))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Generate a credential for a named application.
///
/// The username is derived from the name and a random suffix rather than being
/// the name itself: usernames are not secret, but two applications called
/// `backup` on two hosts should not collide when an operator copies a
/// configuration between them.
pub fn generate(name: &str) -> Result<Credential, CredentialError> {
    let password = random_password();
    let hash = hash(&password)?;

    let slug: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();

    Ok(Credential {
        username: format!(
            "pg_{}_{}",
            if slug.is_empty() { "app" } else { &slug },
            token(6)
        ),
        password,
        hash,
    })
}

/// Hash a password for storage.
pub fn hash(password: &str) -> Result<String, CredentialError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CredentialError::Hash(e.to_string()))
}

/// Whether this password matches the stored hash.
///
/// The comparison inside is constant-time. What this function must not grow is
/// an early return for "no such user" — that is the caller's problem, and the
/// caller solves it by verifying against a dummy hash so that a missing user
/// costs the same as a wrong password.
pub fn verify(password: &str, stored: &str) -> Result<bool, CredentialError> {
    let parsed =
        PasswordHash::new(stored).map_err(|e| CredentialError::StoredHash(e.to_string()))?;

    Ok(argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// A hash to verify against when there is no user.
///
/// Verifying something is the point: returning early for an unknown username
/// makes the response time say whether the username exists, and an attacker
/// with a list of names learns which ones are real without ever guessing a
/// password.
///
/// Generated once per process rather than baked in as a constant, so nothing
/// about it is worth recognising in a capture.
pub fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash(&random_password()).unwrap_or_else(|_| {
            // Only reachable if Argon2 itself cannot be constructed, which is a
            // programming error rather than a runtime condition. A syntactically
            // valid hash keeps the timing shape rather than turning this into a
            // panic on the authentication path.
            "$argon2id$v=19$m=19456,t=1,p=1$c29tZXNhbHRzYWx0$\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_string()
        })
    })
}

/// 128 bits, base32-ish, in groups a person can read aloud.
///
/// Not a passphrase: this is typed into a configuration file once and pasted
/// thereafter, and 128 bits of entropy makes online guessing irrelevant.
fn random_password() -> String {
    let raw = token(26);
    raw.as_bytes()
        .chunks(6)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// `n` characters from an alphabet with no ambiguous glyphs.
///
/// `0`/`O` and `1`/`l` are left out because these are read off a screen and
/// typed into a config file by hand at least once.
fn token(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).expect("the OS provides randomness");
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let stored = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &stored).unwrap());
        assert!(!verify("Correct horse battery staple", &stored).unwrap());
        assert!(!verify("", &stored).unwrap());
    }

    #[test]
    fn two_hashes_of_one_password_differ() {
        // Salted, so a database leak does not reveal that two applications
        // share a password — and so a rainbow table is useless.
        let a = hash("same").unwrap();
        let b = hash("same").unwrap();
        assert_ne!(a, b);
        assert!(verify("same", &a).unwrap() && verify("same", &b).unwrap());
    }

    #[test]
    fn a_generated_credential_is_unguessable_and_readable() {
        let c = generate("backup script").unwrap();

        // The username names the application, so a leaked credential says what
        // leaked it — and carries a random suffix so two hosts' `backup`
        // credentials do not collide.
        assert!(c.username.starts_with("pg_backupscrip"), "{}", c.username);
        assert!(verify(&c.password, &c.hash).unwrap());

        // 26 characters from a 32-symbol alphabet is 130 bits.
        let symbols = c.password.chars().filter(|c| *c != '-').count();
        assert_eq!(symbols, 26);

        // No glyph that is ambiguous on a screen: these get typed by hand once.
        assert!(!c.password.contains(['0', 'O', '1', 'l']), "{}", c.password);
    }

    #[test]
    fn generated_credentials_do_not_repeat() {
        let a = generate("app").unwrap();
        let b = generate("app").unwrap();
        assert_ne!(a.username, b.username);
        assert_ne!(a.password, b.password);
    }

    #[test]
    fn the_dummy_hash_is_verifiable_and_matches_nothing() {
        // Its whole job is to cost the same as a real verification, so it has
        // to parse and run rather than fail fast.
        let dummy = dummy_hash();
        assert!(
            verify("anything", dummy).is_ok(),
            "the dummy hash does not parse, so an unknown user would be fast"
        );
        assert!(!verify("anything", dummy).unwrap());
    }

    #[test]
    fn a_corrupt_stored_hash_is_an_error_rather_than_a_pass() {
        // A row edited by hand must not authenticate everybody.
        assert!(verify("anything", "not a hash").is_err());
        assert!(verify("anything", "").is_err());
    }
}
