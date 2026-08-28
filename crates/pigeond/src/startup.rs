//! Startup, in the order `M1-SCHEMA.md` §5 requires.
//!
//! The order is forced by dependencies, and getting it wrong means either
//! checking something that is not loaded yet or binding a listener before the
//! system is known to work:
//!
//! ```text
//! 1  load and parse TOML
//! 2  validate local paths and permissions
//! 3  open the database, set pragmas
//! 4  run migrations
//! 5  cross-check config against schema
//! 6  prepare the spool
//! 7  build the routing snapshot
//! 8  bind listeners
//! 9  serve
//! ```
//!
//! Steps 1 to 7 live here. Binding and serving belong to the caller, because
//! this function's contract is "everything that can refuse to start has
//! refused" and a bound socket is not part of that.
//!
//! # Step 7 is where the routing rules are enforced
//!
//! `Snapshot::build` is the enforcement point for every invariant SQLite cannot
//! express (`M1-SCHEMA.md` S-2): a reject rule that also forwards, an alias
//! inheriting a default that does not exist, ambiguous wildcards, a forwarding
//! loop. A configuration that fails it is not published, and at startup that
//! aborts — it is local and unambiguous.
//!
//! Its non-fatal findings are reported rather than swallowed. An alias made
//! redundant by a catch-all still routes correctly; a domain that passes every
//! DNS check and is switched off refuses mail on purpose and looks exactly like
//! a fault.
//!
//! # Two kinds of failure
//!
//! Local and unambiguous aborts; remote DNS state warns. That distinction is
//! `ARCHITECTURE.md` §5.1, and it is the reason [`Started::warnings`] exists
//! rather than every check returning `Result`.

use std::path::{Path, PathBuf};

use pigeon_config::{Checked, Config, ConfigError};
use pigeon_db::{Applied, DbError};
use pigeon_route::Snapshot;
use rusqlite::Connection;

/// Everything steps 1 to 6 produced.
pub struct Started {
    pub config: Checked,
    pub db: Connection,
    pub migration: Applied,
    /// The validated routing table. Nothing else can produce one.
    pub snapshot: Snapshot,
    /// Detector state matching `snapshot`, so the worker's first tick compares
    /// against the fingerprint that was actually published.
    pub watcher: pigeon_route::Watcher,
    /// Non-fatal findings, in the order they were made.
    ///
    /// Remote state only. Anything local that is wrong is an error, not an
    /// entry here — see the module note.
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("configuration: {0}")]
    Config(#[from] Box<ConfigError>),

    #[error("database: {0}")]
    Db(#[from] DbError),

    #[error(
        "the DKIM private key for {domain} (selector {selector}) at {path} is not the \
         one published in DNS.\n\n  \
         Every signature it makes would verify as dkim=fail, at the receiver, \
         silently.\n\n  \
         Either restore the matching private key, or generate a new one and publish \
         its record."
    )]
    DkimMismatch {
        domain: String,
        selector: String,
        path: String,
    },

    #[error("DKIM key for {domain} (selector {selector}): {source}")]
    DkimKeyUnreadable {
        domain: String,
        selector: String,
        // Boxed. Unboxed it makes `StartupError` large enough to trip
        // `clippy::result_large_err`, which every `Result` in the startup chain
        // then carries — and it did so on x86_64 while passing on aarch64,
        // because the threshold is a byte count and the layout is not the same.
        #[source]
        source: Box<pigeon_auth::DkimError>,
    },

    #[error(
        "the DKIM private key for {domain} (selector {selector}) at {path} is {mode:04o}. \
         It must be no more permissive than 0600 — it is the one piece of state no backup \
         of the database restores."
    )]
    DkimKeyTooPermissive {
        domain: String,
        selector: String,
        path: String,
        mode: u32,
    },

    #[error("DKIM key for {domain} (selector {selector}): {source}")]
    DkimKeyUnusable {
        domain: String,
        selector: String,
        #[source]
        source: Box<pigeon_config::ValidationError>,
    },

    #[error(
        "alerts.identity {identity} is on {domain}, which this Pigeon manages. An alert \
         about a broken record on that domain would be sent from the domain with the \
         broken record, and destroyed by the fault it exists to report. Use an address \
         on a domain Pigeon does not carry."
    )]
    AlertIdentityIsManaged { identity: String, domain: String },

    #[error("cannot read the routing configuration: {0}")]
    Load(#[from] pigeon_route::LoadError),

    #[error(
        "the routing configuration is not usable: {0}\n\nNothing was published. \
         Mail is not being accepted, because a routing table that cannot answer \
         correctly is worse than one that is missing."
    )]
    Initial(pigeon_route::InitialError),

    #[error(
        "the routing configuration is not usable: {0}\n\nNothing was published. \
         Mail is not being accepted, because a routing table that cannot answer \
         correctly is worse than one that is missing."
    )]
    Routing(#[from] pigeon_route::BuildError),

    #[error("spool {path} is unusable: {source}")]
    Spool {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Run steps 1 to 6.
///
/// `prepare_spool` is passed in rather than called directly so this sequence
/// can be tested against a probe the test controls — and so that the ordering,
/// which is the whole point, stays inside one tested function instead of being
/// reassembled correctly by every caller.
pub async fn start<F, Fut>(config_path: &Path, prepare_spool: F) -> Result<Started, StartupError>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    // 1 and 2. Parsing and validation are separate inside `pigeon-config`, so a
    // TOML syntax error reads differently from an unwritable directory.
    let checked = Config::load_and_validate(config_path).map_err(Box::new)?;
    let config = checked.config().clone();

    // 3. Pragmas — WAL, foreign keys, busy timeout — are set by `open`.
    let mut db = pigeon_db::open(&config.database)?;

    // 4. Aborts on any failure, having taken a backup first.
    let migration = pigeon_db::migrate(&mut db, &config.database)?;

    // 5. The checks that need both halves. Nothing before this point could have
    // run them: the rows do not exist until migrations have.
    let mut warnings = Vec::new();
    check_dkim_keys(&db, &checked)?;
    check_alert_identity(&db, &config)?;
    warn_about_hostname(&config.hostname, &mut warnings);

    // 6. Before the snapshot, because a spool probe is cheap next to reading
    // and validating every routing rule, and both abort.
    prepare_spool(config.spool.clone())
        .await
        .map_err(|source| StartupError::Spool {
            path: config.spool.clone(),
            source,
        })?;

    // 7. The enforcement boundary. Loading transcribes rows and decides
    // nothing; `build` is where every rule about a valid configuration lives.
    //
    // Built through `reload::initial` so the fingerprint the worker compares
    // against is the one behind the table actually published. The *version* is
    // deliberately not captured here: the worker starts with no baseline and
    // rebuilds unconditionally on its first tick, which is what closes the
    // window between this build and the worker starting.
    let (snapshot, reports, watcher) =
        pigeon_route::reload::initial(&db).map_err(StartupError::Initial)?;
    for report in &reports {
        warnings.push(report.to_string());
    }

    Ok(Started {
        config: checked,
        db,
        migration,
        snapshot,
        watcher,
        warnings,
    })
}

/// Every active DKIM key is present, contained, and provably the right one.
///
/// # Existence is not the property
///
/// A key file replaced during a botched rotation, or restored from a backup
/// taken before the last one, exists and passes every permission check — and
/// then signs every message with a key whose public half is not the one in DNS.
/// Every signature verifies as `dkim=fail`, at the receiver, silently, while
/// the daemon reports a clean start.
///
/// So the public key is derived from the private key and compared against the
/// one stored beside it. Until Milestone 1 could do that, this refused to start
/// rather than claiming a check it could not make; it now makes the check.
///
/// Every key is examined, not just the first: a host carrying forty domains
/// that stops at the first good one has verified one fortieth of its signing.
fn check_dkim_keys(db: &Connection, checked: &Checked) -> Result<(), StartupError> {
    for key in pigeon_db::repo::active_dkim_keys(db)? {
        // Containment first: a stored path is operator-editable, and without a
        // root it can name any file the daemon can read.
        let path = checked
            .resolve_key(&key.private_key_path)
            .map_err(|source| StartupError::DkimKeyUnusable {
                domain: key.domain.clone(),
                selector: key.selector.clone(),
                source: Box::new(source),
            })?;

        require_private_key_mode(&path, &key)?;

        let (derived, shape) =
            pigeon_auth::dkim::inspect_private_file(&path).map_err(|source| {
                StartupError::DkimKeyUnreadable {
                    domain: key.domain.clone(),
                    selector: key.selector.clone(),
                    source: Box::new(source),
                }
            })?;

        // The algorithm was recorded and then ignored. A 1024-bit key stored as
        // `rsa2048` matches its own public half perfectly and starts the daemon,
        // while the record in DNS advertises a strength the signing key does not
        // have.
        pigeon_auth::dkim::check_algorithm(&key.algorithm, shape).map_err(|source| {
            StartupError::DkimKeyUnreadable {
                domain: key.domain.clone(),
                selector: key.selector.clone(),
                source: Box::new(source),
            }
        })?;

        if derived != key.public_key {
            return Err(StartupError::DkimMismatch {
                domain: key.domain,
                selector: key.selector,
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

/// A DKIM private key must not be readable by anyone else.
///
/// `SECURITY.md` requires `0600`. It is checked here rather than only when the
/// key is written, because the file outlives the command that created it and
/// nothing else ever looks at it again.
fn require_private_key_mode(
    path: &Path,
    key: &pigeon_db::repo::DkimKey,
) -> Result<(), StartupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|source| StartupError::DkimKeyUnreadable {
            domain: key.domain.clone(),
            selector: key.selector.clone(),
            source: Box::new(pigeon_auth::DkimError::Io {
                path: path.display().to_string(),
                source,
            }),
        })?;
        let mode = meta.permissions().mode() & 0o777;
        // "No bits beyond 0600", not equality: an operator who made it 0400 has
        // been stricter than asked.
        if mode & !0o600 != 0 {
            return Err(StartupError::DkimKeyTooPermissive {
                domain: key.domain.clone(),
                selector: key.selector.clone(),
                path: path.display().to_string(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = (path, key);
    Ok(())
}

/// The alert identity must not be on a domain this Pigeon carries.
///
/// `ALERTING.md`: an alert about a broken DKIM record cannot be sent from the
/// domain with the broken DKIM record. The message is discarded by a receiver
/// honouring `p=reject`, the operator sees nothing, and silence is
/// indistinguishable from health — so the alert is destroyed by precisely the
/// fault it exists to report.
fn check_alert_identity(db: &Connection, config: &Config) -> Result<(), StartupError> {
    if !config.alerts.enabled {
        return Ok(());
    }
    let Some(identity) = config.alerts.identity.as_deref() else {
        return Ok(()); // Already refused by local validation.
    };
    let Ok(parsed) = pigeon_types::Address::parse(identity) else {
        return Ok(()); // Likewise.
    };

    let managed: i64 = db
        .query_row(
            "SELECT count(*) FROM domain WHERE name = ?1",
            [parsed.domain()],
            |r| r.get(0),
        )
        .map_err(DbError::Sqlite)?;

    if managed > 0 {
        return Err(StartupError::AlertIdentityIsManaged {
            identity: identity.to_string(),
            domain: parsed.domain().to_string(),
        });
    }
    Ok(())
}

/// Remote state. Warns, and must never abort.
///
/// `ARCHITECTURE.md` §5.1: a resolver outage must not become a total mail
/// outage across every domain on the host. This reads identically to the two
/// checks above and is the one that must not stop the daemon, which is why the
/// three are written out separately rather than looped over.
fn warn_about_hostname(hostname: &str, warnings: &mut Vec<String>) {
    // The forward and reverse lookups belong to `pigeon-dns` and to the
    // Milestone 5 validator. What is checkable here without a resolver is that
    // the name is not one that can never have public DNS.
    let suspect = hostname.ends_with(".local")
        || hostname.ends_with(".localdomain")
        || hostname.ends_with(".internal")
        || hostname.ends_with(".test")
        || hostname.ends_with(".invalid");

    if suspect {
        warnings.push(format!(
            "hostname {hostname} is in a name space that cannot have public DNS. \
             Receivers check that a sending host's forward and reverse DNS agree, \
             and this one cannot. Mail will be accepted here and distrusted elsewhere."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "pigeond-startup-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(dir.join("keys")).unwrap();
            std::fs::create_dir_all(dir.join("secrets")).unwrap();
            std::fs::create_dir_all(dir.join("spool")).unwrap();
            std::fs::write(dir.join("srs.key"), b"secret").unwrap();

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = |p: PathBuf, m: u32| {
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
                };
                mode(dir.join("keys"), 0o700);
                mode(dir.join("secrets"), 0o700);
                mode(dir.join("srs.key"), 0o600);
            }
            Self { dir }
        }

        /// Write a config file, with `extra` appended.
        fn config(&self, extra: &str) -> PathBuf {
            let d = self.dir.display();
            let toml = format!(
                r#"
hostname = "mx1.example.com"
database = "{d}/pigeon.db"
spool = "{d}/spool"
keys = "{d}/keys"
secrets = "{d}/secrets"
srs_secret_file = "{d}/srs.key"

[smtp.inbound]
listen = "127.0.0.1:0"
{extra}
"#
            );
            let p = self.dir.join("pigeon.toml");
            std::fs::write(&p, toml).unwrap();
            p
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A spool probe that records whether it ran, so ordering can be asserted.
    fn probe(
        ran: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> impl FnOnce(PathBuf) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>>>>
    {
        move |_dir| {
            ran.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn the_startup_error_stays_small() {
        // `clippy::result_large_err` trips at 128 bytes, and every `Result` in
        // the startup chain carries this type. It is a byte count against a
        // layout, so it passed on aarch64 and failed on x86_64 in CI — asserted
        // here so the next growth is caught by a test rather than by a runner.
        let size = std::mem::size_of::<StartupError>();
        assert!(size <= 128, "StartupError is {size} bytes; box a variant");
    }

    #[tokio::test]
    async fn a_valid_configuration_starts_and_migrates() {
        let f = Fixture::new("ok");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("start");

        assert_eq!(started.migration.from, 0);
        assert_eq!(started.migration.to, 1);
        assert!(ran.load(Ordering::SeqCst), "the spool was never prepared");

        // The schema is really there, on the connection that was handed back.
        let n: i64 = started
            .db
            .query_row("SELECT count(*) FROM domain", [], |r| r.get(0))
            .expect("domain table missing");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn the_spool_is_not_touched_when_configuration_is_invalid() {
        // Ordering, asserted rather than assumed. Step 6 must not run if step 2
        // failed — otherwise a daemon that is going to refuse to start still
        // writes into a directory it was never entitled to use.
        let f = Fixture::new("order");
        let path = f.config("");
        std::fs::write(&path, "hostname = \"not-an-fqdn\"\n").unwrap();

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        match start(&path, probe(ran.clone())).await {
            Err(StartupError::Config(_)) => {}
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started on a configuration that should be refused"),
        }
        assert!(
            !ran.load(Ordering::SeqCst),
            "the spool was prepared despite configuration being refused"
        );
    }

    #[tokio::test]
    async fn an_alert_identity_on_a_managed_domain_refuses_to_start() {
        // ALERTING.md: the alert would be sent from the domain it reports on,
        // discarded by a receiver honouring p=reject, and the operator would
        // see silence — which looks exactly like health.
        let f = Fixture::new("alertid");
        let path = f.config(
            r#"
[alerts]
enabled = true
identity = "pigeon@example.com"
to = "me@example.net"
"#,
        );
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // First start creates the schema; the domain has to exist to collide.
        let started = start(&path, probe(ran.clone())).await.expect("first start");
        started
            .db
            .execute(
                "INSERT INTO domain(name, created_at, updated_at) VALUES('example.com', 0, 0)",
                [],
            )
            .unwrap();
        drop(started);

        match start(&path, probe(ran.clone())).await {
            Err(StartupError::AlertIdentityIsManaged { domain, .. }) => {
                assert_eq!(domain, "example.com");
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with an alert identity on a managed domain"),
        }
    }

    #[tokio::test]
    async fn an_alert_identity_off_the_managed_domains_is_fine() {
        let f = Fixture::new("alertok");
        let path = f.config(
            r#"
[alerts]
enabled = true
identity = "pigeon@ops.example.net"
to = "me@example.net"
"#,
        );
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = start(&path, probe(ran.clone())).await.expect("start");
        started
            .db
            .execute(
                "INSERT INTO domain(name, created_at, updated_at) VALUES('example.com', 0, 0)",
                [],
            )
            .unwrap();
        drop(started);

        start(&path, probe(ran)).await.expect("second start");
    }

    /// Two real 2048-bit keypairs, generated once for the whole test binary.
    ///
    /// Real size, because the startup check now verifies the key against the
    /// algorithm recorded for it and a 1024-bit key stored as `rsa2048` is
    /// exactly what it exists to refuse. Generating 2048 bits per test would
    /// cost seconds each, so they are made once and reused.
    ///
    /// Held as plain `String`s rather than `KeyPair`, which is deliberately not
    /// `Clone` — test key material in a static is not wiped, and that is
    /// acceptable here in a way it is not in the daemon.
    fn test_keys() -> &'static [(String, String); 2] {
        static KEYS: std::sync::OnceLock<[(String, String); 2]> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let one = pigeon_auth::KeyPair::generate(2048).expect("generate");
            let two = pigeon_auth::KeyPair::generate(2048).expect("generate");
            [
                (
                    one.private_pem().to_string(),
                    one.public_base64().to_string(),
                ),
                (
                    two.private_pem().to_string(),
                    two.public_base64().to_string(),
                ),
            ]
        })
    }

    /// Write a real keypair into the fixture and record it.
    ///
    /// `public_override` writes a *different* public key beside the private
    /// one, which is the botched-rotation case.
    fn install_dkim_key(f: &Fixture, db: &Connection, public_override: Option<&str>) -> String {
        install_dkim_key_as(f, db, public_override, "rsa2048", 0)
    }

    fn install_dkim_key_as(
        f: &Fixture,
        db: &Connection,
        public_override: Option<&str>,
        algorithm: &str,
        which: usize,
    ) -> String {
        let (private_pem, public_base64) = &test_keys()[which];
        let path = f.dir.join("keys/example.com.key");
        std::fs::write(&path, private_pem).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        db.execute_batch(
            "INSERT OR IGNORE INTO domain(name, created_at, updated_at)
             VALUES('example.com', 0, 0);",
        )
        .unwrap();
        db.execute(
            "INSERT INTO dkim_key(domain_id, selector, algorithm, public_key,
                                  private_key_path, created_at)
             VALUES((SELECT id FROM domain WHERE name='example.com'), 'pigeon', ?2, ?1,
                    'example.com.key', 0)",
            rusqlite::params![public_override.unwrap_or(public_base64), algorithm],
        )
        .unwrap();
        public_base64.clone()
    }

    #[tokio::test]
    async fn a_matching_dkim_key_starts() {
        let f = Fixture::new("dkim-ok");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        install_dkim_key(&f, &started.db, None);
        drop(started);

        start(&path, probe(ran))
            .await
            .expect("a matching key was refused");
    }

    #[tokio::test]
    async fn a_dkim_key_that_is_not_the_published_one_refuses_to_start() {
        // The case an existence check passes and a signature fails: a key file
        // replaced during a botched rotation, or restored from a backup taken
        // before the last one. Every signature it makes verifies as dkim=fail,
        // at the receiver, silently, while the daemon reports a clean start.
        let f = Fixture::new("dkim-mismatch");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        let someone_elses = test_keys()[1].1.clone();
        install_dkim_key(&f, &started.db, Some(&someone_elses));
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimMismatch {
                domain, selector, ..
            }) => {
                assert_eq!(
                    (domain.as_str(), selector.as_str()),
                    ("example.com", "pigeon")
                );
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with a key that is not the one published"),
        }
    }

    #[tokio::test]
    async fn a_key_smaller_than_its_recorded_algorithm_refuses_to_start() {
        // The algorithm column was recorded and then ignored. A 1024-bit key
        // stored as `rsa2048` matches its own public half perfectly, so every
        // other check here passes — while the record published in DNS
        // advertises a strength the signing key does not have.
        let f = Fixture::new("dkim-size");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        let small = pigeon_auth::KeyPair::generate(1024).expect("generate");
        std::fs::write(f.dir.join("keys/example.com.key"), small.private_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                f.dir.join("keys/example.com.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        started
            .db
            .execute_batch(
                "INSERT INTO domain(name, created_at, updated_at) VALUES('example.com',0,0);",
            )
            .unwrap();
        started
            .db
            .execute(
                "INSERT INTO dkim_key(domain_id, selector, algorithm, public_key,
                                      private_key_path, created_at)
                 VALUES(1, 'pigeon', 'rsa2048', ?1, 'example.com.key', 0)",
                [small.public_base64()],
            )
            .unwrap();
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimKeyUnreadable { .. }) => {}
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with a 1024-bit key recorded as rsa2048"),
        }
    }

    #[tokio::test]
    async fn an_ed25519_key_is_refused_rather_than_misparsed() {
        // Not implemented. Without an explicit refusal it reaches the RSA
        // parser and fails with a confusing message about PKCS#8.
        let f = Fixture::new("dkim-ed");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        install_dkim_key_as(&f, &started.db, None, "ed25519", 0);
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimKeyUnreadable { source, .. }) => {
                assert!(
                    matches!(
                        *source,
                        pigeon_auth::DkimError::AlgorithmNotImplemented { .. }
                    ),
                    "{source:?}"
                );
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with an ed25519 key that nothing can use"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_readable_dkim_key_refuses_to_start() {
        use std::os::unix::fs::PermissionsExt;

        let f = Fixture::new("dkim-perms");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        install_dkim_key(&f, &started.db, None);
        drop(started);

        std::fs::set_permissions(
            f.dir.join("keys/example.com.key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimKeyTooPermissive { mode, .. }) => assert_eq!(mode, 0o644),
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with a world-readable DKIM private key"),
        }
    }

    #[tokio::test]
    async fn a_dkim_key_whose_file_is_not_a_key_refuses_to_start() {
        let f = Fixture::new("dkim-garbage");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        install_dkim_key(&f, &started.db, None);
        std::fs::write(f.dir.join("keys/example.com.key"), b"not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                f.dir.join("keys/example.com.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimKeyUnreadable { .. }) => {}
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with a key file that is not a key"),
        }
    }

    #[tokio::test]
    async fn a_dkim_key_outside_the_keys_root_refuses_to_start() {
        // Containment is checked before the deferred derivation, so this must
        // report the escape rather than the unverifiable branch.
        let f = Fixture::new("dkimescape");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        std::fs::write(f.dir.join("outside.key"), b"key").unwrap();
        started
            .db
            .execute_batch(
                "INSERT INTO domain(name, created_at, updated_at) VALUES('example.com', 0, 0);
                 INSERT INTO dkim_key(domain_id, selector, public_key, private_key_path, created_at)
                 VALUES(1, 'pigeon', 'PUB', '../outside.key', 0);",
            )
            .unwrap();
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimKeyUnusable { .. }) => {}
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("a key outside the keys root was accepted"),
        }
    }

    #[tokio::test]
    async fn a_hostname_that_cannot_have_public_dns_warns_without_aborting() {
        // ARCHITECTURE.md §5.1: remote state gates a domain, never the process.
        // This check reads identically to the two above and must behave
        // differently, which is why it is written out separately.
        let f = Fixture::new("hostwarn");
        let path = f.config("");
        std::fs::write(
            &path,
            std::fs::read_to_string(&path)
                .unwrap()
                .replace("mx1.example.com", "mx1.home.local"),
        )
        .unwrap();

        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = start(&path, probe(ran))
            .await
            .expect("a warning aborted startup");

        assert_eq!(started.warnings.len(), 1, "{:?}", started.warnings);
        assert!(
            started.warnings[0].contains("public DNS"),
            "{:?}",
            started.warnings
        );
    }

    #[tokio::test]
    async fn restarting_is_a_no_op_and_takes_no_backup() {
        let f = Fixture::new("restart");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        start(&path, probe(ran.clone())).await.expect("first");
        let second = start(&path, probe(ran)).await.expect("second");

        assert!(second.migration.is_empty());
        assert_eq!(
            second.migration.backup, None,
            "a restart copied the database"
        );
    }
}
