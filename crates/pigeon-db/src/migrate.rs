//! The migration runner.
//!
//! The invariants are in `docs/M1-SCHEMA.md` §2 and are the product; this
//! module is small on purpose. Each one is named in the code that enforces it
//! so a reader can check the two against each other.
//!
//! # Why the whole batch is one transaction
//!
//! SQLite has no nested transactions. "A transaction per migration" and "a lock
//! held for the whole run" cannot both be implemented — a second
//! `BEGIN IMMEDIATE` fails with *cannot start a transaction within a
//! transaction*. So the batch is the unit, which is also the stronger property:
//! the daemon never boots three migrations into a five-migration upgrade.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::DbError;

/// One migration, compiled in.
///
/// `sql` is `&[u8]` rather than `&str` because the checksum covers the exact
/// bytes that were reviewed (I2, I10). Nothing normalises them in between.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static [u8],
}

/// Every migration this binary knows, in order.
///
/// Append only. Editing a released entry is what the checksum in I2 exists to
/// catch, and it will catch it on the next start.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial",
        sql: include_bytes!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "queue",
        sql: include_bytes!("../migrations/0002_queue.sql"),
    },
    Migration {
        version: 3,
        name: "claim-token",
        sql: include_bytes!("../migrations/0003_claim_token.sql"),
    },
    Migration {
        version: 4,
        name: "abandoned-notification",
        sql: include_bytes!("../migrations/0004_abandoned.sql"),
    },
];

/// What a run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Version before the run.
    pub from: u32,
    /// Version after it.
    pub to: u32,
    /// Migrations applied, in order.
    pub versions: Vec<u32>,
    /// Where the pre-migration backup was written, if one was needed.
    pub backup: Option<PathBuf>,
}

impl Applied {
    /// Whether anything was applied. A no-op run is the common case.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }
}

fn checksum(sql: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(sql);
    format!("{:x}", h.finalize())
}

/// Bring `conn` up to the latest known schema version.
///
/// `db_path` is where the database lives; a pre-migration backup is written
/// beside it. Passing it explicitly rather than asking the connection keeps
/// this testable against a path the caller controls.
pub fn migrate(conn: &mut Connection, db_path: &Path) -> Result<Applied, DbError> {
    // The bookkeeping table is created outside the batch, and separately from
    // migration 1, because the runner has to read it before it can know whether
    // migration 1 has run. `IF NOT EXISTS` rather than a migration: this table's
    // shape is the runner's own contract, not part of the schema it manages.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migration (
             version    INTEGER PRIMARY KEY,
             name       TEXT    NOT NULL,
             checksum   TEXT    NOT NULL,
             applied_at INTEGER NOT NULL
         ) STRICT;",
    )
    .map_err(DbError::Sqlite)?;

    let applied = read_applied(conn)?;
    verify_history(&applied)?;

    let current = applied.last().map(|(v, _)| *v).unwrap_or(0);
    let latest = MIGRATIONS.last().map(|m| m.version).unwrap_or(0);

    // I5: a database from the future. A binary that does not know about a
    // column keeps working and writes rows the newer constraints would have
    // rejected, and the damage surfaces after the *next* upgrade.
    if current > latest {
        return Err(DbError::DatabaseFromTheFuture {
            database: current,
            binary: latest,
        });
    }

    let pending: Vec<&Migration> = MIGRATIONS.iter().filter(|m| m.version > current).collect();
    if pending.is_empty() {
        return Ok(Applied {
            from: current,
            to: current,
            versions: Vec::new(),
            backup: None,
        });
    }

    // I3a. Taken before the transaction opens, because its purpose is to
    // survive the transaction failing in a way that leaves the file damaged.
    //
    // A backup that cannot be written aborts. Refusing to migrate is
    // recoverable; migrating with no way back is not, and I1 makes restore the
    // only rollback path there is.
    let backup = back_up(conn, db_path, current)?;

    // Foreign keys OFF for the batch, and `foreign_key_check` inside it.
    //
    // This is SQLite's own documented procedure for altering tables, and it is
    // why the check exists at all: a future migration that rebuilds a table
    // must drop and recreate it, which transiently violates every key pointing
    // at it. Enforcement during the batch would make that impossible; the check
    // before commit gives the same guarantee at the only moment it matters.
    //
    // Neither pragma can be set inside a transaction, so both sit outside it.
    conn.pragma_update(None, "foreign_keys", false)
        .map_err(DbError::Sqlite)?;

    let result = apply_batch(conn, &pending);

    // Restored whether or not the batch succeeded: the caller gets a connection
    // with the pragma every other connection has, or an error.
    conn.pragma_update(None, "foreign_keys", true)
        .map_err(DbError::Sqlite)?;

    result?;

    Ok(Applied {
        from: current,
        to: latest,
        versions: pending.iter().map(|m| m.version).collect(),
        backup: Some(backup),
    })
}

/// Apply every pending migration in one transaction (I3, I6).
fn apply_batch(conn: &mut Connection, pending: &[&Migration]) -> Result<(), DbError> {
    // I6: `Immediate` takes the write lock now rather than on first write, so
    // two processes starting in the same second cannot both decide the same
    // migration is pending. This transaction *is* the lock; there is no second
    // one.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(DbError::Sqlite)?;

    for m in pending {
        let sql = std::str::from_utf8(m.sql)
            .map_err(|_| DbError::MigrationNotUtf8 { version: m.version })?;

        tx.execute_batch(sql)
            .map_err(|e| DbError::MigrationFailed {
                version: m.version,
                name: m.name,
                source: e,
            })?;

        tx.execute(
            "INSERT INTO schema_migration (version, name, checksum, applied_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![m.version, m.name, checksum(m.sql), now()],
        )
        .map_err(DbError::Sqlite)?;
    }

    // I9. Inside the transaction, so a rollback takes it back too — verified.
    let latest = pending.last().expect("pending is non-empty").version;
    tx.pragma_update(None, "user_version", latest)
        .map_err(DbError::Sqlite)?;

    // I8. Inside the batch, so a migration that breaks referential integrity is
    // rolled back rather than reported after the fact.
    let violations = foreign_key_violations(&tx)?;
    if !violations.is_empty() {
        return Err(DbError::ForeignKeyViolations(violations));
    }

    tx.commit().map_err(DbError::Sqlite)
}

/// Rows reported by `PRAGMA foreign_key_check`, as `table:rowid` pairs.
fn foreign_key_violations(conn: &Connection) -> Result<Vec<String>, DbError> {
    let mut stmt = conn
        .prepare("PRAGMA foreign_key_check")
        .map_err(DbError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| {
            let table: String = r.get(0)?;
            let rowid: Option<i64> = r.get(1)?;
            Ok(match rowid {
                Some(id) => format!("{table}:{id}"),
                None => table,
            })
        })
        .map_err(DbError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::Sqlite)
}

/// Read what has been applied, in version order.
fn read_applied(conn: &Connection) -> Result<Vec<(u32, String)>, DbError> {
    let mut stmt = conn
        .prepare("SELECT version, checksum FROM schema_migration ORDER BY version")
        .map_err(DbError::Sqlite)?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?)))
        .map_err(DbError::Sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::Sqlite)
}

/// I2 and I4: nothing applied has been edited, and there are no gaps.
fn verify_history(applied: &[(u32, String)]) -> Result<(), DbError> {
    for (i, (version, recorded)) in applied.iter().enumerate() {
        // I4. Dense from 1, so position determines version. A gap means a
        // migration was lost in a merge and the runner must not skip it.
        let expected_version = (i + 1) as u32;
        if *version != expected_version {
            return Err(DbError::VersionGap {
                expected: expected_version,
                found: *version,
            });
        }

        let Some(known) = MIGRATIONS.iter().find(|m| m.version == *version) else {
            // Applied, and this binary has never heard of it. Distinct from
            // DatabaseFromTheFuture: the versions may be in range while the
            // content is unknown.
            return Err(DbError::UnknownMigration { version: *version });
        };

        // I2. An edited migration is caught on the next start, which is where
        // that mistake is cheap.
        let actual = checksum(known.sql);
        if actual != *recorded {
            return Err(DbError::ChecksumMismatch {
                version: *version,
                name: known.name,
                recorded: recorded.clone(),
                actual,
            });
        }
    }
    Ok(())
}

/// Write a durable pre-migration copy beside the database (I3a).
fn back_up(conn: &Connection, db_path: &Path, from: u32) -> Result<PathBuf, DbError> {
    let dir = db_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = db_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pigeon.db".to_string());

    // Named for the version being migrated *from*, so what it contains is
    // evident without opening it.
    let path = dir.join(format!("{stem}.pre-migration-v{from}.bak"));

    let write = || -> Result<(), DbError> {
        // SQLite's Backup API, not a file copy: a copy taken while a WAL exists
        // is not a consistent database, and the failure shows up as corruption
        // at the moment it is needed.
        conn.backup(rusqlite::MAIN_DB, &path, None)
            .map_err(DbError::Sqlite)?;

        // fsync the file and its directory. An unflushed backup is indistinguishable
        // from a real one until the power goes out, which is one of the times it
        // is most likely to be wanted.
        let f = fs::File::open(&path).map_err(|e| DbError::BackupFailed {
            path: path.clone(),
            source: e,
        })?;
        f.sync_all().map_err(|e| DbError::BackupFailed {
            path: path.clone(),
            source: e,
        })?;
        let d = fs::File::open(dir).map_err(|e| DbError::BackupFailed {
            path: path.clone(),
            source: e,
        })?;
        d.sync_all().map_err(|e| DbError::BackupFailed {
            path: path.clone(),
            source: e,
        })
    };

    write()?;
    Ok(path)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A private directory that removes itself. Same reasoning as `pigeond`'s:
    /// a dependency for this is a new entry in the reviewed dependency set for
    /// something the standard library already does.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "pigeon-db-test-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }
        fn db(&self) -> PathBuf {
            self.0.join("pigeon.db")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fresh(tag: &str) -> (TempDir, Connection) {
        let tmp = TempDir::new(tag);
        let conn = crate::open(&tmp.db()).expect("open");
        (tmp, conn)
    }

    #[test]
    fn a_fresh_database_gets_the_whole_schema() {
        let (tmp, mut conn) = fresh("fresh");
        let applied = migrate(&mut conn, &tmp.db()).expect("migrate");

        assert_eq!(applied.from, 0);
        let latest = MIGRATIONS.last().unwrap().version;
        assert_eq!(applied.to, latest);
        assert_eq!(
            applied.versions,
            (1..=latest).collect::<Vec<_>>(),
            "a fresh database should apply every migration in order"
        );

        // The tables the design actually specifies, not merely "some tables".
        let mut names: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "alias",
                "alias_destination",
                "delivery",
                "delivery_event",
                "destination",
                "dkim_key",
                "domain",
                "message",
                "original_recipient",
                "principal",
                "principal_grant",
                "recipient_delivery",
                "relay",
                "schema_migration",
                "sender_identity",
                "setting",
            ]
        );

        // Indexes, explicitly. Three of these carry properties the schema
        // review found by executing it rather than reading it, and an index
        // silently dropped from a migration is invisible in a table listing:
        // `principal_grant_domain_wide` is what stops `auth revoke` reporting
        // success while leaving a duplicate domain-wide grant, and
        // `dkim_key_one_active` is what stops two active keys per algorithm.
        let mut indexes: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        indexes.sort();
        assert_eq!(
            indexes,
            vec![
                "alias_destination_by_destination",
                // The queue's indexes. Each one is a rule rather than a
                // performance note: due work, owed notifications, and leases
                // that may have expired are the three scans a worker makes,
                // and a table of terminal rows is what it would scan without
                // them.
                "delivery_abandoned",
                "delivery_by_message",
                "delivery_due",
                "delivery_event_by_delivery",
                "delivery_leases",
                "delivery_owed",
                "dkim_key_one_active",
                "domain_by_catchall_dest",
                "domain_by_default_dest",
                "domain_by_notify_dest",
                "domain_by_relay",
                "principal_grant_by_domain",
                "principal_grant_domain_wide",
                "principal_grant_identity",
            ]
        );

        // I9: readable by an operator with nothing but sqlite3.
        assert_eq!(
            crate::schema_version(&conn).unwrap(),
            MIGRATIONS.last().unwrap().version
        );
    }

    /// The constraints the schema review established, checked through
    /// `rusqlite` rather than the `sqlite3` binary — so what is tested is the
    /// bundled SQLite that actually ships (M1-SCHEMA.md §8).
    #[test]
    fn the_schema_refuses_what_the_review_established_it_should() {
        let (tmp, mut conn) = fresh("constraints");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        conn.execute_batch(
            "INSERT INTO relay(name,host,created_at) VALUES('primary','r.test',0);
             INSERT INTO destination(local,domain) VALUES('me','example.net');
             INSERT INTO domain(name,created_at,updated_at) VALUES('example.com',0,0);
             INSERT INTO sender_identity(domain_id,local,created_at) VALUES(1,'hello',0);
             INSERT INTO principal(name,username,password_hash,created_at)
               VALUES('mac','pg_1','h',0);
             INSERT INTO dkim_key(domain_id,selector,public_key,private_key_path,created_at)
               VALUES(1,'pigeon','PUB','/k/e.key',0);",
        )
        .expect("fixtures");

        let refused = |sql: &str, why: &str| {
            assert!(
                conn.execute_batch(sql).is_err(),
                "schema accepted something it must refuse: {why}"
            );
        };
        let allowed = |sql: &str, why: &str| {
            assert!(
                conn.execute_batch(sql).is_ok(),
                "schema refused something it must allow: {why}"
            );
        };

        refused(
            "INSERT INTO domain(name,status,created_at,updated_at) VALUES('a.com','suspended',0,0)",
            "'suspended' was removed from the lifecycle; it is a flag now",
        );
        refused(
            "INSERT INTO domain(name,delivery_mode,relay_id,created_at,updated_at)
             VALUES('b.com','direct',1,0,0)",
            "direct mode carrying a relay_id reads as configured relay delivery",
        );
        refused(
            "INSERT INTO domain(name,catchall_enabled,created_at,updated_at) VALUES('c.com',1,0,0)",
            "a catch-all with no effective destination accepts every address and routes nowhere",
        );
        refused(
            "INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'hello',0);
             INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'Hello',0)",
            "Hello and hello are one alias; only one of them would ever match",
        );
        refused(
            "INSERT INTO principal_grant(principal_id,domain_id,local,created_at)
             VALUES(1,1,'nobody',0)",
            "a grant may not name an identity absent from the domain's allowlist",
        );
        refused(
            "INSERT INTO dkim_key(domain_id,selector,algorithm,public_key,private_key_path,created_at)
             VALUES(1,'p2','rsa2048','P','/k/2',0)",
            "two active RSA keys make the signer's choice arbitrary",
        );

        allowed(
            "INSERT INTO domain(name,status,inbound_enabled,created_at,updated_at)
             VALUES('d.com','error',0,0,0)",
            "gated by DNS *and* administratively disabled — both axes at once",
        );
        allowed(
            "INSERT INTO principal_grant(principal_id,domain_id,local,created_at)
             VALUES(1,1,NULL,0)",
            "a domain-wide grant skips the composite key because local is NULL",
        );
        refused(
            "INSERT INTO principal_grant(principal_id,domain_id,local,created_at)
             VALUES(1,1,NULL,0)",
            "a second domain-wide grant is what makes auth revoke a lie",
        );

        // The UPDATE path, which is the one that actually loses mail: a
        // catch-all left accepting every address after its inherited
        // destination is cleared from a different column.
        allowed(
            "INSERT INTO domain(name,catchall_enabled,default_destination_id,created_at,updated_at)
             VALUES('e.com',1,1,0,0)",
            "a catch-all inheriting the domain default",
        );
        refused(
            "UPDATE domain SET default_destination_id=NULL WHERE name='e.com'",
            "clearing the default that an enabled catch-all inherits",
        );
    }

    #[test]
    fn migrating_twice_does_nothing_the_second_time() {
        let (tmp, mut conn) = fresh("idempotent");
        migrate(&mut conn, &tmp.db()).expect("first");

        let second = migrate(&mut conn, &tmp.db()).expect("second");
        assert!(second.is_empty(), "re-applied a migration: {second:?}");
        let latest = MIGRATIONS.last().unwrap().version;
        assert_eq!(second.from, latest);
        assert_eq!(second.to, latest);

        // No backup for a no-op run. Otherwise every restart of a
        // fully-migrated daemon copies the database for nothing.
        assert_eq!(second.backup, None);
    }

    #[test]
    fn a_backup_is_written_before_anything_is_applied() {
        // I3a. Forward-only migrations make restore the only rollback path, so
        // an invariant that depends on a backup nobody took is a plan.
        let (tmp, mut conn) = fresh("backup");
        let applied = migrate(&mut conn, &tmp.db()).expect("migrate");

        let backup = applied.backup.expect("no backup was taken");
        assert!(backup.exists(), "backup path does not exist: {backup:?}");
        assert!(
            backup.to_string_lossy().contains("pre-migration-v0"),
            "backup is not named for the version it was taken from: {backup:?}"
        );

        // It must be a usable database, not a partial copy. Opening it and
        // reading its version is the cheapest proof that it is.
        let restored = Connection::open(&backup).expect("backup does not open");
        let v: u32 = restored
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 0, "the backup contains the post-migration schema");
    }

    #[test]
    fn an_edited_migration_is_refused() {
        // I2. The developer who edits a released migration finds out on the
        // next start, which is where that mistake is cheap.
        let (tmp, mut conn) = fresh("checksum");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        conn.execute(
            "UPDATE schema_migration SET checksum = 'nonsense' WHERE version = 1",
            [],
        )
        .unwrap();

        match migrate(&mut conn, &tmp.db()) {
            Err(DbError::ChecksumMismatch { version, .. }) => assert_eq!(version, 1),
            other => panic!("an edited migration was accepted: {other:?}"),
        }
    }

    #[test]
    fn a_database_from_the_future_is_refused() {
        // I5. The alternative is a binary that does not know about a column
        // writing rows the newer constraints would have rejected.
        let (tmp, mut conn) = fresh("future");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        // One past whatever this build knows, so the test does not need
        // editing every time a migration is added.
        let future = MIGRATIONS.last().unwrap().version + 1;
        conn.execute(
            "INSERT INTO schema_migration (version, name, checksum, applied_at)
             VALUES (?1, 'from-a-newer-build', 'x', 0)",
            [future],
        )
        .unwrap();

        match migrate(&mut conn, &tmp.db()) {
            Err(DbError::UnknownMigration { version }) => assert_eq!(version, future),
            other => panic!("a future database was accepted: {other:?}"),
        }
    }

    #[test]
    fn a_gap_in_the_history_is_refused() {
        // I4. A gap means a migration was lost in a merge, and skipping it
        // silently is how a column nothing created gets queried.
        let (tmp, mut conn) = fresh("gap");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        conn.execute("DELETE FROM schema_migration WHERE version = 1", [])
            .unwrap();

        match migrate(&mut conn, &tmp.db()) {
            Err(DbError::VersionGap { expected, found }) => {
                assert_eq!((expected, found), (1, 2));
            }
            other => panic!("a gap was accepted: {other:?}"),
        }
    }

    #[test]
    fn a_failing_batch_leaves_no_trace() {
        // I3. The whole point of one transaction for the batch: the daemon
        // never boots part-way through an upgrade.
        let tmp = TempDir::new("atomic");
        let mut conn = crate::open(&tmp.db()).expect("open");

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migration (
                 version INTEGER PRIMARY KEY, name TEXT NOT NULL,
                 checksum TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        )
        .unwrap();

        let good = Migration {
            version: 1,
            name: "good",
            sql: b"CREATE TABLE a (x INTEGER) STRICT;",
        };
        let bad = Migration {
            version: 2,
            name: "bad",
            sql: b"CREATE TABLE b (x INTEGER) STRICT; THIS IS NOT SQL;",
        };

        let err = apply_batch(&mut conn, &[&good, &bad]).expect_err("bad SQL was accepted");
        assert!(
            matches!(err, DbError::MigrationFailed { version: 2, .. }),
            "{err:?}"
        );

        // The *first* migration must be gone too. A runner with a transaction
        // per migration would have left table `a` and version 1 behind.
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('a','b')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "a partially applied batch was committed");

        let rows: i64 = conn
            .query_row("SELECT count(*) FROM schema_migration", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "a rolled-back migration was still recorded");

        assert_eq!(
            crate::schema_version(&conn).unwrap(),
            0,
            "user_version survived a rollback"
        );
    }

    #[test]
    fn foreign_keys_are_on_for_every_connection() {
        // Per connection, not persistent — the single most common way a SQLite
        // schema's referential integrity turns out to be decorative.
        let (tmp, mut conn) = fresh("fk");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        let on: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1, "foreign keys were left off after migrating");

        // A second connection, opened the ordinary way, must have them too.
        let other = crate::open(&tmp.db()).expect("second connection");
        let on: i64 = other
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);

        // And they must actually bite.
        let err = other.execute(
            "INSERT INTO alias (domain_id, pattern, created_at) VALUES (999, 'x', 0)",
            [],
        );
        assert!(
            err.is_err(),
            "an alias for a nonexistent domain was accepted"
        );
    }

    #[test]
    fn a_read_only_connection_cannot_write() {
        // ARCHITECTURE.md §3.3 has mutations go through the daemon so there is
        // one writer. A connection that *cannot* write enforces that rather
        // than trusting every command not to.
        let (tmp, mut conn) = fresh("readonly");
        migrate(&mut conn, &tmp.db()).expect("migrate");

        let ro = crate::open_read_only(&tmp.db()).expect("open read-only");
        let err = ro.execute(
            "INSERT INTO setting (key, value, updated_at) VALUES ('k','v',0)",
            [],
        );
        assert!(err.is_err(), "a read-only connection wrote to the database");
    }

    #[test]
    fn the_checksum_covers_exact_bytes() {
        // I10: `include_bytes!`, so nothing normalises between what was
        // reviewed and what is verified. A CRLF rewrite must change the sum —
        // which is why .gitattributes pins *.sql to LF.
        assert_ne!(
            checksum(b"CREATE TABLE a (x INTEGER);\n"),
            checksum(b"CREATE TABLE a (x INTEGER);\r\n"),
            "line endings do not affect the checksum, so the eol=lf pin is pointless"
        );
    }

    #[test]
    fn every_known_migration_is_dense_and_ordered() {
        // I4, checked against the compiled-in list rather than a database, so a
        // badly numbered migration fails in CI before it can reach one.
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                m.version,
                (i + 1) as u32,
                "migration {} is out of order or leaves a gap",
                m.name
            );
        }
    }
}
