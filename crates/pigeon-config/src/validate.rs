//! Local validation of bootstrap configuration.
//!
//! Everything here is local and unambiguous, so a failure aborts startup. The
//! distinction is `ARCHITECTURE.md` §5.1: local misconfiguration stops the
//! process, remote DNS state gates a domain.
//!
//! # Existence is not the property
//!
//! Several checks here look like "does this path exist" and are not. A keys
//! directory that exists and is world-readable, a TLS private key that exists
//! and is `0644`, a spool that exists on a read-only filesystem — each passes
//! an existence check and fails at the moment it matters, which for a mail
//! server is after a sender has been told `250`.

use std::path::{Path, PathBuf};

use crate::Config;

/// A configuration whose local claims have been checked.
///
/// The type is the evidence. A `Checked` cannot be constructed except by
/// [`validate`], so a function taking one does not have to wonder whether
/// somebody remembered.
#[derive(Debug, Clone)]
pub struct Checked {
    config: Config,
    keys: PathBuf,
    secrets: PathBuf,
}

impl Checked {
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The canonical keys root. Every stored key path must resolve inside it.
    pub fn keys_root(&self) -> &Path {
        &self.keys
    }

    /// The canonical secrets root, for `relay.secret_ref`.
    pub fn secrets_root(&self) -> &Path {
        &self.secrets
    }

    /// Resolve a stored key path against the keys root, refusing escapes.
    ///
    /// `dkim_key.private_key_path` comes from the database, which an operator
    /// can edit. Without containment a row could name any file the daemon can
    /// read, and the failure would look like a working DKIM configuration.
    pub fn resolve_key(&self, stored: &str) -> Result<PathBuf, ValidationError> {
        contain(&self.keys, stored, "DKIM key")
    }

    /// Resolve `relay.secret_ref`, which is a name rather than a path.
    pub fn resolve_secret(&self, name: &str) -> Result<PathBuf, ValidationError> {
        if name.contains('/') || name.contains('\\') {
            return Err(ValidationError::SecretRefIsNotAName {
                name: name.to_string(),
            });
        }
        contain(&self.secrets, name, "relay secret")
    }
}

/// Resolve `candidate` against `root` and require the result to stay inside it.
///
/// Canonicalises both, so `..` and symlinks are resolved before the comparison
/// rather than after — a prefix check on an uncanonicalised path is satisfied
/// by `/var/lib/pigeon/keys/../../../etc/shadow`.
fn contain(root: &Path, candidate: &str, what: &str) -> Result<PathBuf, ValidationError> {
    let joined = if Path::new(candidate).is_absolute() {
        PathBuf::from(candidate)
    } else {
        root.join(candidate)
    };

    let real = joined
        .canonicalize()
        .map_err(|source| ValidationError::Missing {
            what: what.to_string(),
            path: joined.clone(),
            source,
        })?;

    if !real.starts_with(root) {
        return Err(ValidationError::EscapesRoot {
            what: what.to_string(),
            path: real,
            root: root.to_path_buf(),
        });
    }
    Ok(real)
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{what} {path} is missing or unreadable: {source}")]
    Missing {
        what: String,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A configured helper that cannot be used as one.
    ///
    /// Separate from `Missing` because the reason is not always a file that is
    /// not there: a scanner can exist and not be executable, which reads very
    /// differently to an operator.
    #[error("the {what} at {path} cannot be used: {reason}")]
    Unusable {
        what: &'static str,
        path: PathBuf,
        reason: String,
    },

    #[error("{what} {path} is outside the configured root {root}")]
    EscapesRoot {
        what: String,
        path: PathBuf,
        root: PathBuf,
    },

    #[error(
        "relay secret_ref {name:?} looks like a path. It is a name, resolved \
         against the configured secrets directory."
    )]
    SecretRefIsNotAName { name: String },

    #[error("{what} {path} is {actual:04o}; it must be {expected:04o} — it is a secret")]
    TooPermissive {
        what: String,
        path: PathBuf,
        actual: u32,
        expected: u32,
    },

    #[error("{what} {path} is not a directory")]
    NotADirectory { what: String, path: PathBuf },

    #[error("hostname is empty")]
    HostnameEmpty,

    #[error(
        "hostname {0:?} is not a fully qualified domain name. It is used in the SMTP \
         banner, in EHLO and in Received: headers, and receivers distrust a host that \
         cannot name itself."
    )]
    HostnameNotFqdn(String),

    #[error(
        "submission requires STARTTLS to be enabled. Turning it off means passwords \
         cross the network in the clear."
    )]
    StarttlsRequired,

    #[error("submission is configured on {listen} but {what} is not set")]
    SubmissionIncomplete { listen: String, what: &'static str },

    #[error("inbound TLS is half configured: {what} is not set, so STARTTLS would not be offered")]
    InboundTlsIncomplete { what: &'static str },

    #[error("alerts are enabled but {what} is not set")]
    AlertsIncomplete { what: &'static str },

    #[error(
        "alerts.identity {0:?} is not a valid address. Alerts are sent as it, so a \
         malformed one produces silence, which is indistinguishable from health."
    )]
    AlertIdentityInvalid(String),

    #[error("alerts.to {0:?} is not a valid address")]
    AlertRecipientInvalid(String),

    #[error(
        "alerts.breaker_threshold is {0}; it is a share of domains and must be between \
         0 and 1"
    )]
    BreakerOutOfRange(f64),

    #[error("alerts.confirm_checks is 0, so a single resolver timeout would raise an alert")]
    ConfirmChecksZero,
}

/// Check every local claim the configuration makes.
pub fn validate(config: Config) -> Result<Checked, ValidationError> {
    check_hostname(&config.hostname)?;

    // The database's *directory*, not the file: a fresh install has no database
    // yet, and WAL needs to create `-wal` and `-shm` siblings, so the directory
    // is what has to be writable.
    let db_dir = config
        .database
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_dir("database directory", db_dir)?;

    let keys = require_dir("keys directory", &config.keys)?;
    require_mode("keys directory", &keys, 0o700)?;

    let secrets = require_dir("secrets directory", &config.secrets)?;
    require_mode("secrets directory", &secrets, 0o700)?;

    require_mode("SRS secret", &config.srs_secret_file, 0o600)?;

    check_inbound(&config)?;
    check_scanner(&config)?;
    check_submission(&config)?;
    check_alerts(&config)?;

    Ok(Checked {
        config,
        keys,
        secrets,
    })
}

fn check_hostname(hostname: &str) -> Result<(), ValidationError> {
    if hostname.trim().is_empty() {
        return Err(ValidationError::HostnameEmpty);
    }
    // A bare `localhost` in a Received: header, or in EHLO, is what a
    // misconfigured host looks like to a receiver — and this value cannot be
    // fixed later without every message in between carrying it.
    if !hostname.contains('.') || hostname.starts_with('.') || hostname.ends_with('.') {
        return Err(ValidationError::HostnameNotFqdn(hostname.to_string()));
    }
    Ok(())
}

/// Inbound TLS: both files or neither, and readable if present.
///
/// Half a pair is the dangerous state. A certificate with no key would leave
/// `STARTTLS` unadvertised while the operator believes it is on, and the
/// mistake is invisible — mail keeps flowing, in the clear.
fn check_inbound(config: &Config) -> Result<(), ValidationError> {
    let inbound = &config.smtp.inbound;
    match (&inbound.tls_certificate, &inbound.tls_private_key) {
        (None, None) => Ok(()),
        (Some(cert), Some(key)) => {
            require_readable("inbound TLS certificate", cert)?;
            require_mode("inbound TLS private key", key, 0o600)?;
            Ok(())
        }
        (Some(_), None) => Err(ValidationError::InboundTlsIncomplete {
            what: "tls_private_key",
        }),
        (None, Some(_)) => Err(ValidationError::InboundTlsIncomplete {
            what: "tls_certificate",
        }),
    }
}

fn check_submission(config: &Config) -> Result<(), ValidationError> {
    let s = &config.smtp.submission;

    // Checked whether or not submission is configured. A file that turns it on
    // later should not be the first time anyone discovers the flag was off.
    if !s.require_starttls {
        return Err(ValidationError::StarttlsRequired);
    }

    let Some(listen) = s.listen else {
        return Ok(());
    };

    let cert = s
        .tls_certificate
        .as_ref()
        .ok_or(ValidationError::SubmissionIncomplete {
            listen: listen.to_string(),
            what: "tls_certificate",
        })?;
    let key = s
        .tls_private_key
        .as_ref()
        .ok_or(ValidationError::SubmissionIncomplete {
            listen: listen.to_string(),
            what: "tls_private_key",
        })?;

    require_readable("TLS certificate", cert)?;
    require_mode("TLS private key", key, 0o600)?;
    Ok(())
}

/// The scanner has to exist and be executable, and its timeout has to be a
/// timeout.
///
/// Checked at startup because the alternative is a daemon that starts cleanly
/// and then refuses every message transiently — a total mail stoppage whose
/// cause is one missing file.
fn check_scanner(config: &Config) -> Result<(), ValidationError> {
    let Some(path) = &config.abuse.scanner else {
        return Ok(());
    };

    let meta = std::fs::metadata(path).map_err(|e| ValidationError::Unusable {
        what: "content scanner",
        path: path.clone(),
        reason: e.to_string(),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(ValidationError::Unusable {
                what: "content scanner",
                path: path.clone(),
                reason: "not executable".into(),
            });
        }
    }
    let _ = meta;

    if config.abuse.scanner_timeout_seconds == 0 {
        return Err(ValidationError::Unusable {
            what: "content scanner",
            path: path.clone(),
            reason: "scanner_timeout_seconds is 0, so every message would time out".into(),
        });
    }
    Ok(())
}

fn check_alerts(config: &Config) -> Result<(), ValidationError> {
    let a = &config.alerts;

    if a.breaker_threshold <= 0.0 || a.breaker_threshold > 1.0 {
        return Err(ValidationError::BreakerOutOfRange(a.breaker_threshold));
    }

    if !a.enabled {
        return Ok(());
    }

    // Zero would alert on a single resolver timeout, and the point of the
    // confirmation window is that one timeout is noise.
    if a.confirm_checks == 0 {
        return Err(ValidationError::ConfirmChecksZero);
    }

    let identity = a
        .identity
        .as_deref()
        .ok_or(ValidationError::AlertsIncomplete { what: "identity" })?;
    let to =
        a.to.as_deref()
            .ok_or(ValidationError::AlertsIncomplete { what: "to" })?;

    if pigeon_types::Address::parse(identity).is_err() {
        return Err(ValidationError::AlertIdentityInvalid(identity.to_string()));
    }
    if pigeon_types::Address::parse(to).is_err() {
        return Err(ValidationError::AlertRecipientInvalid(to.to_string()));
    }
    Ok(())
}

/// Require an existing directory, and return its canonical path.
fn require_dir(what: &str, path: &Path) -> Result<PathBuf, ValidationError> {
    let real = path
        .canonicalize()
        .map_err(|source| ValidationError::Missing {
            what: what.to_string(),
            path: path.to_path_buf(),
            source,
        })?;
    if !real.is_dir() {
        return Err(ValidationError::NotADirectory {
            what: what.to_string(),
            path: real,
        });
    }
    Ok(real)
}

fn require_readable(what: &str, path: &Path) -> Result<(), ValidationError> {
    std::fs::File::open(path)
        .map(|_| ())
        .map_err(|source| ValidationError::Missing {
            what: what.to_string(),
            path: path.to_path_buf(),
            source,
        })
}

/// Require a path to exist and be no more permissive than `expected`.
///
/// The comparison is "no bits beyond `expected`", not equality: an operator who
/// has made a key `0400` has been stricter than asked, and refusing that would
/// be pedantry with a security cost.
fn require_mode(what: &str, path: &Path, expected: u32) -> Result<(), ValidationError> {
    let meta = std::fs::metadata(path).map_err(|source| ValidationError::Missing {
        what: what.to_string(),
        path: path.to_path_buf(),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = meta.permissions().mode() & 0o777;
        if actual & !expected != 0 {
            return Err(ValidationError::TooPermissive {
                what: what.to_string(),
                path: path.to_path_buf(),
                actual,
                expected,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (meta, expected);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "pigeon-config-test-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }

        fn dir(&self, name: &str, mode: u32) -> PathBuf {
            let p = self.0.join(name);
            std::fs::create_dir_all(&p).unwrap();
            set_mode(&p, mode);
            p
        }

        fn file(&self, name: &str, mode: u32) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, b"x").unwrap();
            set_mode(&p, mode);
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set_mode(p: &Path, mode: u32) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = (p, mode);
    }

    /// A configuration whose every local claim is true.
    fn good(tmp: &TempDir) -> Config {
        Config {
            hostname: "mx1.example.test".into(),
            database: tmp.0.join("pigeon.db"),
            spool: tmp.0.join("spool"),
            keys: tmp.dir("keys", 0o700),
            secrets: tmp.dir("secrets", 0o700),
            srs_secret_file: tmp.file("srs.key", 0o600),
            smtp: crate::Smtp::default(),
            alerts: crate::Alerts::default(),
            abuse: crate::Abuse::default(),
        }
    }

    #[test]
    fn a_correct_configuration_validates() {
        let tmp = TempDir::new("good");
        validate(good(&tmp)).expect("a valid configuration was refused");
    }

    #[test]
    fn inbound_tls_must_be_configured_in_full_or_not_at_all() {
        // Half a pair is the dangerous state: a certificate with no key leaves
        // STARTTLS unadvertised while the operator believes it is on, and the
        // mistake is invisible — mail keeps flowing, in the clear.
        let tmp = TempDir::new("inbound-tls");

        let mut c = good(&tmp);
        c.smtp.inbound.tls_certificate = Some(tmp.file("cert.pem", 0o644));
        match validate(c) {
            Err(ValidationError::InboundTlsIncomplete { what }) => {
                assert_eq!(what, "tls_private_key")
            }
            other => panic!("accepted a certificate with no key: {other:?}"),
        }

        let mut c = good(&tmp);
        c.smtp.inbound.tls_private_key = Some(tmp.file("key.pem", 0o600));
        assert!(
            matches!(
                validate(c),
                Err(ValidationError::InboundTlsIncomplete {
                    what: "tls_certificate"
                })
            ),
            "accepted a key with no certificate"
        );

        // Both, and the pair validates.
        let mut c = good(&tmp);
        c.smtp.inbound.tls_certificate = Some(tmp.file("cert2.pem", 0o644));
        c.smtp.inbound.tls_private_key = Some(tmp.file("key2.pem", 0o600));
        validate(c).expect("a complete inbound TLS pair was refused");
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_inbound_tls_key_is_refused() {
        // The key that authenticates this host to every sender that encrypts.
        let tmp = TempDir::new("inbound-tls-perm");
        let mut c = good(&tmp);
        c.smtp.inbound.tls_certificate = Some(tmp.file("cert.pem", 0o644));
        c.smtp.inbound.tls_private_key = Some(tmp.file("key.pem", 0o644));
        match validate(c) {
            Err(ValidationError::TooPermissive { actual, .. }) => assert_eq!(actual, 0o644),
            other => panic!("accepted a world-readable TLS key: {other:?}"),
        }
    }

    #[test]
    fn a_hostname_that_is_not_fqdn_is_refused() {
        // It lands in every Received: header this host ever writes, and cannot
        // be corrected retroactively for the mail in between.
        let tmp = TempDir::new("host");
        for bad in ["localhost", "", "  ", ".example.com", "example.com."] {
            let mut c = good(&tmp);
            c.hostname = bad.into();
            assert!(
                validate(c).is_err(),
                "accepted a hostname that is not an FQDN: {bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_keys_directory_is_refused() {
        // DKIM private keys are the one piece of state no backup regenerates.
        let tmp = TempDir::new("keysperm");
        let mut c = good(&tmp);
        c.keys = tmp.dir("loose-keys", 0o755);
        match validate(c) {
            Err(ValidationError::TooPermissive { actual, .. }) => assert_eq!(actual, 0o755),
            other => panic!("accepted a world-readable keys directory: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_stricter_mode_than_required_is_accepted() {
        // An operator who made a key 0400 has been stricter than asked.
        // Refusing that would be pedantry with a security cost.
        let tmp = TempDir::new("strict");
        let mut c = good(&tmp);
        c.srs_secret_file = tmp.file("srs-strict.key", 0o400);
        validate(c).expect("refused a stricter mode than required");
    }

    #[cfg(unix)]
    #[test]
    fn a_readable_srs_secret_is_refused() {
        // Not cosmetic: the SRS secret authenticates bounce return paths, so
        // anyone who can read it can forge them.
        let tmp = TempDir::new("srs");
        let mut c = good(&tmp);
        c.srs_secret_file = tmp.file("loose.key", 0o644);
        assert!(validate(c).is_err(), "accepted a readable SRS secret");
    }

    #[test]
    fn starttls_cannot_be_turned_off() {
        // Checked even when submission is not configured: a file that turns it
        // on later should not be the first time anyone notices the flag.
        let tmp = TempDir::new("tls");
        let mut c = good(&tmp);
        c.smtp.submission.require_starttls = false;
        assert!(matches!(
            validate(c),
            Err(ValidationError::StarttlsRequired)
        ));
    }

    #[test]
    fn submission_without_tls_material_is_refused() {
        let tmp = TempDir::new("subm");
        let mut c = good(&tmp);
        c.smtp.submission.listen = Some("0.0.0.0:587".parse().unwrap());
        match validate(c) {
            Err(ValidationError::SubmissionIncomplete { what, .. }) => {
                assert_eq!(what, "tls_certificate");
            }
            other => panic!("accepted submission with no certificate: {other:?}"),
        }
    }

    #[test]
    fn enabled_alerts_need_an_identity_and_a_recipient() {
        let tmp = TempDir::new("alerts");
        let mut c = good(&tmp);
        c.alerts.enabled = true;
        assert!(matches!(
            validate(c),
            Err(ValidationError::AlertsIncomplete { what: "identity" })
        ));

        let mut c = good(&tmp);
        c.alerts.enabled = true;
        c.alerts.identity = Some("pigeon@ops.example.test".into());
        assert!(matches!(
            validate(c),
            Err(ValidationError::AlertsIncomplete { what: "to" })
        ));
    }

    #[test]
    fn a_malformed_alert_identity_is_refused() {
        // A malformed identity produces no alerts, and the symptom of no
        // alerts is silence — indistinguishable from everything working.
        let tmp = TempDir::new("alertaddr");
        let mut c = good(&tmp);
        c.alerts.enabled = true;
        c.alerts.identity = Some("not-an-address".into());
        c.alerts.to = Some("me@example.test".into());
        assert!(matches!(
            validate(c),
            Err(ValidationError::AlertIdentityInvalid(_))
        ));
    }

    #[test]
    fn a_confirmation_window_of_zero_is_refused() {
        let tmp = TempDir::new("confirm");
        let mut c = good(&tmp);
        c.alerts.enabled = true;
        c.alerts.identity = Some("pigeon@ops.example.test".into());
        c.alerts.to = Some("me@example.test".into());
        c.alerts.confirm_checks = 0;
        assert!(matches!(
            validate(c),
            Err(ValidationError::ConfirmChecksZero)
        ));
    }

    #[test]
    fn a_breaker_threshold_outside_zero_to_one_is_refused() {
        let tmp = TempDir::new("breaker");
        for bad in [0.0, -0.5, 1.5] {
            let mut c = good(&tmp);
            c.alerts.breaker_threshold = bad;
            assert!(validate(c).is_err(), "accepted breaker_threshold {bad}");
        }
    }

    // ------------------------------------------------------- path containment

    #[test]
    fn a_key_path_escaping_the_root_is_refused() {
        // `dkim_key.private_key_path` comes from a database an operator can
        // edit. Without containment a row names any file the daemon can read,
        // and it looks like a working DKIM configuration.
        let tmp = TempDir::new("escape");
        let checked = validate(good(&tmp)).expect("validate");
        let outside = tmp.file("outside.key", 0o600);

        for attempt in [
            "../outside.key",
            "./../outside.key",
            &outside.to_string_lossy(),
        ] {
            match checked.resolve_key(attempt) {
                Err(ValidationError::EscapesRoot { .. }) => {}
                other => panic!("key path escaped the root via {attempt:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_symlink_out_of_the_keys_root_is_refused() {
        // A prefix check on an uncanonicalised path is satisfied by a symlink
        // that lives inside the root and points anywhere.
        #[cfg(unix)]
        {
            let tmp = TempDir::new("symlink");
            let c = good(&tmp);
            let keys = c.keys.clone();
            let target = tmp.file("elsewhere.key", 0o600);
            std::os::unix::fs::symlink(&target, keys.join("sneaky.key")).unwrap();

            let checked = validate(c).expect("validate");
            match checked.resolve_key("sneaky.key") {
                Err(ValidationError::EscapesRoot { .. }) => {}
                other => panic!("a symlink escaped the keys root: {other:?}"),
            }
        }
    }

    #[test]
    fn a_key_inside_the_root_resolves() {
        let tmp = TempDir::new("inside");
        let c = good(&tmp);
        std::fs::write(c.keys.join("example.com.key"), b"k").unwrap();
        let checked = validate(c).expect("validate");
        let p = checked
            .resolve_key("example.com.key")
            .expect("a key inside the root was refused");
        assert!(p.starts_with(checked.keys_root()));
    }

    #[test]
    fn a_relay_secret_ref_that_looks_like_a_path_is_refused() {
        // secret_ref is a name. Keeping the password out of the row solves
        // nothing if the row can name /etc/shadow.
        let tmp = TempDir::new("secretref");
        let checked = validate(good(&tmp)).expect("validate");
        for attempt in ["../../etc/shadow", "/etc/shadow", "sub/dir"] {
            assert!(
                matches!(
                    checked.resolve_secret(attempt),
                    Err(ValidationError::SecretRefIsNotAName { .. })
                        | Err(ValidationError::EscapesRoot { .. })
                ),
                "accepted a secret_ref that is a path: {attempt:?}"
            );
        }
    }

    #[test]
    fn durations_parse_only_in_the_documented_forms() {
        use crate::humantime_serde_compat::parse;
        assert_eq!(parse("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse("6h"), Some(Duration::from_secs(21_600)));
        assert_eq!(parse("2d"), Some(Duration::from_secs(172_800)));

        // Deliberately narrow. Partial flexibility reads as a bug when it
        // fails: "1h30m" parsing while "90 minutes" does not is worse than
        // neither working.
        for bad in ["", "6", "6 h", "1h30m", "six hours", "-1h", "6y"] {
            assert_eq!(parse(bad), None, "accepted {bad:?}");
        }
    }
}
