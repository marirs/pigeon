//! Turning a spooled message into queued work, and the one failure that must
//! never be guessed at.
//!
//! Acceptance is ordered (`M3-DESIGN.md` §4): the spool file becomes durable,
//! then the queue rows commit, then the sender is told `250`. The interesting
//! part is what happens when the middle step fails, because two of the three
//! possible outcomes look identical from the caller's side and only one of them
//! makes it safe to delete the file.
//!
//! # A failed `COMMIT` is not the same as "nothing committed"
//!
//! A statement that fails *before* the commit is unambiguous: the transaction
//! is rolled back and nothing exists. A `COMMIT` that returns an error is not.
//! SQLite can fail a commit with the transaction still active, and it can fail
//! to report a commit that reached the disk — an I/O error on the reply path,
//! a killed process between the write and the return.
//!
//! Treating that as "nothing committed" and deleting the spool file destroys a
//! message that rows already refer to. Nothing recovers it: the body is not in
//! the database, and the sender has been told nothing yet but will retry into a
//! queue that already believes it has the message.
//!
//! So the asymmetry is deliberate and total:
//!
//! - **Leaking a durable file** is recoverable — orphan recovery collects it.
//! - **Duplicating after a retry** is recoverable — the recipient sees two.
//! - **Deleting a file committed rows point at** is permanent loss.
//!
//! Which is why the only outcome that authorises deletion is one where
//! non-commit has been *established*, by reading the database back through a
//! fresh connection. If that read itself fails, the file stays.

use rusqlite::{Connection, TransactionBehavior};

use crate::SpoolId;

/// One message ready to be queued: the finished bytes are already on disk.
#[derive(Debug, Clone)]
pub struct Acceptance {
    pub spool_id: SpoolId,
    /// The SRS return path, as it will be transmitted.
    pub return_path: String,
    /// What the sender used, for the log and the DSN.
    pub original_sender: String,
    pub size_bytes: i64,
    pub routing_revision: i64,
    pub routing_fingerprint: Vec<u8>,
    /// The recipients the sender named, before routing resolved anything.
    pub original_recipients: Vec<String>,
    /// The resolved destinations, each naming which of the sender's recipients
    /// led to it.
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone)]
pub struct Destination {
    pub address: String,
    /// Indices into [`Acceptance::original_recipients`]. Several, because
    /// deduplication merges recipients onto one destination and a DSN has to
    /// name the address the sender wrote.
    pub from_recipients: Vec<usize>,
}

/// Why an acceptance did not complete, and — the point of the type — whether
/// the caller may delete what it spooled.
#[derive(Debug)]
pub enum AcceptFailure {
    /// Nothing committed, established by the failure happening before the
    /// commit was attempted. The caller **must** remove the spool files: they
    /// are orphans, and leaving them costs a sweep.
    NotCommitted(rusqlite::Error),

    /// The commit failed and the outcome is **unknown**, or reconciliation
    /// could not establish it.
    ///
    /// The caller must keep the spool files and answer transiently. If rows did
    /// commit, the message is queued and will be delivered; if they did not,
    /// orphan recovery collects the file and the sender's retry re-accepts it.
    /// Both are survivable. Deleting is not.
    Uncertain(String),
}

impl std::fmt::Display for AcceptFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCommitted(e) => write!(f, "nothing was queued: {e}"),
            Self::Uncertain(m) => write!(f, "the queue transaction's outcome is unknown: {m}"),
        }
    }
}

impl std::error::Error for AcceptFailure {}

impl AcceptFailure {
    /// Whether the caller may remove what it spooled.
    ///
    /// A method rather than a `matches!` at each call site, so the rule has one
    /// definition and reads the same everywhere it is applied.
    pub fn spool_may_be_removed(&self) -> bool {
        matches!(self, Self::NotCommitted(_))
    }
}

/// Queue every group of one submission, in one transaction.
///
/// One transaction for all of them, not one each: a `250` covers the whole
/// submission, so a crash between two commits would tell the sender everything
/// was accepted while half of it existed — and their retry would duplicate the
/// half that survived.
///
/// `db_path` is used only to reconcile an uncertain commit, on a *fresh*
/// connection: the one that failed may be in an unusable state, and asking it
/// what happened is asking the thing that just failed.
pub fn accept(
    conn: &mut Connection,
    db_path: &std::path::Path,
    groups: &[Acceptance],
    now: i64,
) -> Result<Vec<i64>, AcceptFailure> {
    accept_with(conn, db_path, groups, now, |tx| tx.commit())
}

/// [`accept`], with the commit injectable.
///
/// The seam exists because the uncertain-commit path cannot otherwise be
/// tested: a `COMMIT` that fails with the outcome unknown is exactly what does
/// not happen on demand, and a rule that has never executed is a comment.
fn accept_with(
    conn: &mut Connection,
    db_path: &std::path::Path,
    groups: &[Acceptance],
    now: i64,
    commit: impl FnOnce(rusqlite::Transaction<'_>) -> rusqlite::Result<()>,
) -> Result<Vec<i64>, AcceptFailure> {
    // IMMEDIATE, so two acceptances cannot both read and then both write.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(AcceptFailure::NotCommitted)?;

    let mut ids = Vec::with_capacity(groups.len());
    for group in groups {
        match insert(&tx, group, now) {
            Ok(id) => ids.push(id),
            // Before the commit: the rollback is automatic and nothing exists.
            Err(e) => return Err(AcceptFailure::NotCommitted(e)),
        }
    }

    match commit(tx) {
        Ok(()) => Ok(ids),
        Err(e) => {
            // The one place guessing is forbidden. Read the database back and
            // find out, on a connection that has not just failed.
            match reconcile(db_path, groups) {
                Reconciled::Committed => Ok(ids),
                Reconciled::Absent => Err(AcceptFailure::NotCommitted(e)),
                Reconciled::Unknown(why) => Err(AcceptFailure::Uncertain(format!(
                    "commit failed ({e}) and the database could not be read back ({why})"
                ))),
            }
        }
    }
}

/// What a fresh connection says about a commit whose result was not reported.
#[derive(Debug, PartialEq, Eq)]
pub enum Reconciled {
    /// Every group is present. The commit landed.
    Committed,
    /// No group is present. The commit did not land.
    Absent,
    /// The database could not be read, or the groups disagree — some present
    /// and some not, which no single transaction can produce and therefore
    /// means something is wrong that guessing will not fix.
    Unknown(String),
}

/// Ask a fresh connection whether these messages exist.
pub fn reconcile(db_path: &std::path::Path, groups: &[Acceptance]) -> Reconciled {
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => return Reconciled::Unknown(e.to_string()),
    };

    let mut present = 0usize;
    for group in groups {
        let found: rusqlite::Result<i64> = conn.query_row(
            "SELECT count(*) FROM message WHERE spool_id = ?1",
            [group.spool_id.as_str()],
            |r| r.get(0),
        );
        match found {
            Ok(n) if n > 0 => present += 1,
            Ok(_) => {}
            Err(e) => return Reconciled::Unknown(e.to_string()),
        }
    }

    if present == groups.len() {
        Reconciled::Committed
    } else if present == 0 {
        Reconciled::Absent
    } else {
        // A partial result cannot come from one transaction. Something else
        // wrote, or the database is damaged; either way the spool file stays.
        Reconciled::Unknown(format!(
            "{present} of {} messages are present, which no single transaction produces",
            groups.len()
        ))
    }
}

/// One message, its recipients, its deliveries and the mapping between them.
fn insert(tx: &rusqlite::Transaction<'_>, group: &Acceptance, now: i64) -> rusqlite::Result<i64> {
    tx.execute(
        "INSERT INTO message(spool_id, return_path, original_sender, size_bytes,
                             received_at, routing_revision, routing_fingerprint)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            group.spool_id.as_str(),
            group.return_path,
            group.original_sender,
            group.size_bytes,
            now,
            group.routing_revision,
            group.routing_fingerprint,
        ],
    )?;
    let message_id = tx.last_insert_rowid();

    let mut recipient_ids = Vec::with_capacity(group.original_recipients.len());
    for address in &group.original_recipients {
        tx.execute(
            "INSERT INTO original_recipient(message_id, address) VALUES(?1, ?2)",
            rusqlite::params![message_id, address],
        )?;
        recipient_ids.push(tx.last_insert_rowid());
    }

    for destination in &group.destinations {
        tx.execute(
            "INSERT INTO delivery(message_id, destination, next_attempt_at) VALUES(?1, ?2, ?3)",
            rusqlite::params![message_id, destination.address, now],
        )?;
        let delivery_id = tx.last_insert_rowid();

        for index in &destination.from_recipients {
            let Some(recipient_id) = recipient_ids.get(*index) else {
                // A destination naming a recipient that does not exist is a
                // caller bug, and one that would produce a DSN unable to say
                // which address failed. Refused rather than skipped.
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "destination {} names recipient {index}, which was not supplied",
                    destination.address
                )));
            };
            tx.execute(
                "INSERT INTO recipient_delivery(original_recipient_id, delivery_id)
                 VALUES(?1, ?2)",
                rusqlite::params![recipient_id, delivery_id],
            )?;
        }
    }

    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(tag: &str) -> (std::path::PathBuf, Connection) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-accept-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut conn, &path).unwrap();
        (path, conn)
    }

    fn group(spool: &str, destinations: &[&str]) -> Acceptance {
        Acceptance {
            spool_id: SpoolId::new(spool).unwrap(),
            return_path: "SRS0=tag=AAA=remote.test=alice@pigeon.test".into(),
            original_sender: "alice@remote.test".into(),
            size_bytes: 1024,
            routing_revision: 7,
            routing_fingerprint: vec![0xab; 32],
            original_recipients: vec!["hello@example.com".into()],
            destinations: destinations
                .iter()
                .map(|d| Destination {
                    address: (*d).to_string(),
                    from_recipients: vec![0],
                })
                .collect(),
        }
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn one_submission_commits_as_one_transaction() {
        let (path, mut conn) = db("groups");
        let groups = vec![
            group("msg-a", &["a@provider.example"]),
            group("msg-b", &["b@provider.example"]),
        ];

        let ids = accept(&mut conn, &path, &groups, 100).expect("accept");
        assert_eq!(ids.len(), 2);
        assert_eq!(count(&conn, "message"), 2);
        assert_eq!(count(&conn, "delivery"), 2);
        assert_eq!(count(&conn, "original_recipient"), 2);
        assert_eq!(count(&conn, "recipient_delivery"), 2);
    }

    #[test]
    fn a_failure_before_the_commit_leaves_nothing() {
        // The unambiguous case: the second group collides, so the first one's
        // rows are rolled back too. The caller may remove both spool files.
        let (path, mut conn) = db("precommit");
        let groups = vec![
            group("msg-a", &["a@provider.example"]),
            group("msg-a", &["b@provider.example"]),
        ];

        let err = accept(&mut conn, &path, &groups, 100).unwrap_err();
        assert!(err.spool_may_be_removed(), "{err}");
        assert_eq!(count(&conn, "message"), 0, "a partial submission survived");
    }

    #[test]
    fn a_commit_that_landed_but_reported_an_error_is_an_acceptance() {
        // The case that must not delete anything. The commit succeeds and then
        // reports a failure — an I/O error on the reply path, or a process
        // killed between the write and the return.
        let (path, mut conn) = db("landed");
        let groups = vec![group("msg-a", &["a@provider.example"])];

        let ids = accept_with(&mut conn, &path, &groups, 100, |tx| {
            tx.commit()?;
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(10), // SQLITE_IOERR
                Some("the reply never arrived".into()),
            ))
        })
        .expect("a committed submission was reported as failed");

        assert_eq!(ids.len(), 1);
        assert_eq!(count(&conn, "message"), 1);
    }

    #[test]
    fn a_commit_that_did_not_land_is_established_not_assumed() {
        let (path, mut conn) = db("rolled-back");
        let groups = vec![group("msg-a", &["a@provider.example"])];

        let err = accept_with(&mut conn, &path, &groups, 100, |tx| {
            tx.rollback()?;
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(10),
                Some("commit failed".into()),
            ))
        })
        .unwrap_err();

        assert!(
            err.spool_may_be_removed(),
            "a rolled-back submission was not established as such: {err}"
        );
        assert_eq!(count(&conn, "message"), 0);
    }

    #[test]
    fn an_unreadable_database_keeps_the_spool_file() {
        // Reconciliation itself failing is the third outcome, and it is the one
        // where guessing would be most tempting. The file stays and the sender
        // is answered transiently.
        let (_path, mut conn) = db("unreadable");
        let groups = vec![group("msg-a", &["a@provider.example"])];
        let missing = std::path::Path::new("/nonexistent/directory/pigeon.db");

        let err = accept_with(&mut conn, missing, &groups, 100, |tx| {
            tx.rollback()?;
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(10),
                Some("commit failed".into()),
            ))
        })
        .unwrap_err();

        assert!(
            !err.spool_may_be_removed(),
            "an unreadable database authorised deleting a spool file: {err}"
        );
        assert!(matches!(err, AcceptFailure::Uncertain(_)), "{err:?}");
    }

    #[test]
    fn a_partial_result_is_unknown_rather_than_absent() {
        // Some groups present and some not cannot come from one transaction, so
        // something else wrote or the database is damaged. Either way the files
        // stay.
        let (path, mut conn) = db("partial");
        let committed = vec![group("msg-a", &["a@provider.example"])];
        accept(&mut conn, &path, &committed, 100).unwrap();

        let both = vec![
            group("msg-a", &["a@provider.example"]),
            group("msg-b", &["b@provider.example"]),
        ];
        match reconcile(&path, &both) {
            Reconciled::Unknown(why) => assert!(why.contains("1 of 2"), "{why}"),
            other => panic!("a partial result was not treated as unknown: {other:?}"),
        }
    }

    #[test]
    fn a_destination_naming_a_recipient_that_does_not_exist_is_refused() {
        // It would produce a delivery whose DSN cannot say which address the
        // sender wrote, which is the thing `recipient_delivery` exists for.
        let (path, mut conn) = db("bad-index");
        let mut g = group("msg-a", &["a@provider.example"]);
        g.destinations[0].from_recipients = vec![7];

        let err = accept(&mut conn, &path, &[g], 100).unwrap_err();
        assert!(err.spool_may_be_removed(), "{err}");
        assert_eq!(count(&conn, "message"), 0);
    }
}
