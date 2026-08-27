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
//! 7  build the routing snapshot     <- not yet; see below
//! 8  bind listeners
//! 9  serve
//! ```
//!
//! Steps 1 to 6 live here. Binding and serving belong to the caller, because
//! this function's contract is "everything that can refuse to start has
//! refused" and a bound socket is not part of that.
//!
//! # Step 7 does not exist yet
//!
//! The routing snapshot is the enforcement point for every invariant SQLite
//! cannot express (`M1-SCHEMA.md` S-2), and it is not written. Until it is,
//! there are no repositories and no mutating commands — a write that cannot be
//! validated against a proposed snapshot has nothing validating it, so building
//! the thing that creates invalid rows before the thing that refuses them would
//! be the wrong order.
//!
//! # Two kinds of failure
//!
//! Local and unambiguous aborts; remote DNS state warns. That distinction is
//! `ARCHITECTURE.md` §5.1, and it is the reason [`Started::warnings`] exists
//! rather than every check returning `Result`.

use std::path::{Path, PathBuf};

use pigeon_config::{Checked, Config, ConfigError};
use pigeon_db::{Applied, DbError};
use rusqlite::Connection;

/// Everything steps 1 to 6 produced.
pub struct Started {
    pub config: Checked,
    pub db: Connection,
    pub migration: Applied,
    /// Non-fatal findings, in the order they were made.
    ///
    /// Remote state only. Anything local that is wrong is an error, not an
    /// entry here — see the module note.
    pub warnings: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("configuration: {0}")]
    Config(#[from] ConfigError),

    #[error("database: {0}")]
    Db(#[from] DbError),

    #[error(
        "DKIM key for {domain} (selector {selector}) cannot be verified: this build \
         cannot derive a public key from a private one, so it cannot tell whether the \
         key on disk is the one published in DNS. Refusing to start rather than sign \
         mail that may never verify."
    )]
    DkimUnverifiable { domain: String, selector: String },

    #[error("DKIM key for {domain} (selector {selector}): {source}")]
    DkimKeyUnusable {
        domain: String,
        selector: String,
        #[source]
        source: pigeon_config::ValidationError,
    },

    #[error(
        "alerts.identity {identity} is on {domain}, which this Pigeon manages. An alert \
         about a broken record on that domain would be sent from the domain with the \
         broken record, and destroyed by the fault it exists to report. Use an address \
         on a domain Pigeon does not carry."
    )]
    AlertIdentityIsManaged { identity: String, domain: String },

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
    let checked = Config::load_and_validate(config_path)?;
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

    // 6. Last, because a spool probe is the most expensive check and there is
    // no point paying for it if the database was going to refuse anyway.
    prepare_spool(config.spool.clone())
        .await
        .map_err(|source| StartupError::Spool {
            path: config.spool.clone(),
            source,
        })?;

    Ok(Started {
        config: checked,
        db,
        migration,
        warnings,
    })
}

/// Every active DKIM key is present, contained, and provably the right one.
///
/// # The last part is not implemented, and this refuses rather than pretends
///
/// An existence check is not the property. A key file replaced during a botched
/// rotation, or restored from a backup taken before the last one, exists,
/// passes every permission check, and then signs every message with a key whose
/// public half is not the one in DNS. Every signature verifies as `dkim=fail`,
/// at the receiver, silently, while the daemon reports a clean start.
///
/// Deriving the public key from the private one needs an RSA implementation
/// that this workspace does not yet carry — it arrives with DKIM key
/// *generation*, which is the same Milestone 1 item. Until then a row that
/// cannot be verified stops startup.
///
/// That costs nothing today: `dkim_key` rows are created by `pigeon domain
/// add`, which does not exist, because mutating commands wait for the snapshot
/// builder. The check therefore has nothing to check — and saying so in code
/// that fails loudly is the difference between a deferred branch and a comment
/// claiming a guarantee the code does not provide.
fn check_dkim_keys(db: &Connection, checked: &Checked) -> Result<(), StartupError> {
    let mut stmt = db
        .prepare(
            "SELECT d.name, k.selector, k.private_key_path
             FROM dkim_key k JOIN domain d ON d.id = k.domain_id
             WHERE k.state = 'active'",
        )
        .map_err(DbError::Sqlite)?;

    let mut rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(DbError::Sqlite)?;

    // The first active key is enough to refuse on, so this takes one row rather
    // than iterating. When the derivation below is implemented this becomes a
    // loop over every key; until then, looping would only choose which of
    // several unverifiable keys to name in the error.
    let Some(row) = rows.next() else {
        return Ok(());
    };
    let (domain, selector, path) = row.map_err(DbError::Sqlite)?;

    // Containment first: a stored path is operator-editable, and without a root
    // it can name any file the daemon can read.
    checked
        .resolve_key(&path)
        .map_err(|source| StartupError::DkimKeyUnusable {
            domain: domain.clone(),
            selector: selector.clone(),
            source,
        })?;

    // DEFERRED (Milestone 1, with DKIM key generation): derive the public key
    // from the private key and compare it with `dkim_key.public_key`.
    Err(StartupError::DkimUnverifiable { domain, selector })
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

    #[tokio::test]
    async fn an_unverifiable_dkim_key_refuses_to_start() {
        // The deferred branch, asserted to actually refuse. A comment saying
        // "public key derivation is not implemented" next to code that starts
        // anyway is the exact pattern this project keeps finding.
        let f = Fixture::new("dkim");
        let path = f.config("");
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let started = start(&path, probe(ran.clone())).await.expect("first start");
        std::fs::write(f.dir.join("keys/example.com.key"), b"key").unwrap();
        started
            .db
            .execute_batch(
                "INSERT INTO domain(name, created_at, updated_at) VALUES('example.com', 0, 0);
                 INSERT INTO dkim_key(domain_id, selector, public_key, private_key_path, created_at)
                 VALUES(1, 'pigeon', 'PUB', 'example.com.key', 0);",
            )
            .unwrap();
        drop(started);

        match start(&path, probe(ran)).await {
            Err(StartupError::DkimUnverifiable { domain, selector }) => {
                assert_eq!(
                    (domain.as_str(), selector.as_str()),
                    ("example.com", "pigeon")
                );
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("started with a DKIM key it cannot verify"),
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
