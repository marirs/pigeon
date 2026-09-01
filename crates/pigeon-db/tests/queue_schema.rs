//! What the queue schema refuses.
//!
//! Every constraint here encodes a rule from `M3-DESIGN.md` §3, and each test
//! is the failure that rule prevents. Checked through `rusqlite` rather than
//! the `sqlite3` binary, so what is tested is the bundled SQLite that ships
//! (`M1-SCHEMA.md` §8).

use rusqlite::Connection;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-queue-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("pigeon.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn migrated(tag: &str) -> (TempDir, Connection) {
    let tmp = TempDir::new(tag);
    let mut conn = pigeon_db::open(&tmp.db()).unwrap();
    pigeon_db::migrate(&mut conn, &tmp.db()).unwrap();
    (tmp, conn)
}

/// One accepted message, with no deliveries yet.
fn message(conn: &Connection, spool: &str) -> i64 {
    conn.execute(
        "INSERT INTO message(spool_id, return_path, original_sender, size_bytes,
                             received_at, routing_revision, routing_fingerprint)
         VALUES(?1, 'SRS0=tag=AAA=remote.test=alice@pigeon.test', 'alice@remote.test',
                1024, 0, 1, x'00')",
        [spool],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn queued(conn: &Connection, message_id: i64, destination: &str) -> i64 {
    conn.execute(
        "INSERT INTO delivery(message_id, destination, next_attempt_at) VALUES(?1, ?2, 0)",
        rusqlite::params![message_id, destination],
    )
    .unwrap();
    conn.last_insert_rowid()
}

fn refused(conn: &Connection, sql: &str) -> String {
    match conn.execute(sql, []) {
        Ok(_) => panic!("accepted, and should not have: {sql}"),
        Err(e) => e.to_string(),
    }
}

// ------------------------------------------------------------------ fan-out

#[test]
fn one_destination_cannot_appear_twice_in_a_message() {
    // Two aliases resolving to one mailbox is one delivery: the message is one
    // message, and sending it twice is a duplicate the recipient cannot
    // distinguish from a loop.
    let (_t, conn) = migrated("dup-dest");
    let m = message(&conn, "spool-1");
    queued(&conn, m, "mailbox@provider.example");

    let e = refused(
        &conn,
        &format!(
            "INSERT INTO delivery(message_id, destination, next_attempt_at)
             VALUES({m}, 'mailbox@provider.example', 0)"
        ),
    );
    assert!(e.contains("UNIQUE"), "{e}");
}

#[test]
fn the_same_destination_in_two_messages_is_two_deliveries() {
    // The other half of the rule. Two recipient domains reaching one mailbox
    // are two messages with different signed bytes (R-2), and suppressing one
    // would silently drop mail the sender asked to send.
    let (_t, conn) = migrated("cross-message");
    let a = message(&conn, "spool-a");
    let b = message(&conn, "spool-b");
    queued(&conn, a, "mailbox@provider.example");
    queued(&conn, b, "mailbox@provider.example");

    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM delivery WHERE destination = 'mailbox@provider.example'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 2);
}

// -------------------------------------------------------------------- leases

#[test]
fn a_claim_and_delivering_are_the_same_fact() {
    // A deferred row holding a claim is a row no expiry sweep reclaims and no
    // worker touches — mail that stops moving with nothing to say why.
    let (_t, conn) = migrated("lease");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    // Half a claim: an owner with no expiry. The equivalence below does not
    // catch this on its own — an incomplete pair reads as "not claimed", which
    // matches a queued row — so it is a constraint of its own.
    let e = refused(
        &conn,
        &format!("UPDATE delivery SET claimed_by = 'worker-1' WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "an owner with no lease: {e}");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET lease_expires_at = 60 WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "a lease with no owner: {e}");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET claim_token = 'tok' WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "a token with no owner: {e}");

    // A complete claim on a row that is not delivering.
    let e = refused(
        &conn,
        &format!(
            "UPDATE delivery SET claimed_by='worker-1', claim_token='tok', lease_expires_at=60
              WHERE id = {d}"
        ),
    );
    assert!(e.contains("CHECK"), "a claim without delivering: {e}");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET state = 'delivering', next_attempt_at = NULL WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "delivering without a claim: {e}");

    // And the pair together is accepted.
    conn.execute(
        &format!(
            "UPDATE delivery
                SET state='delivering', claimed_by='worker-1', claim_token='tok',
                    lease_expires_at=60, next_attempt_at=NULL, attempts=attempts+1
              WHERE id = {d}"
        ),
        [],
    )
    .unwrap();
}

#[test]
fn scheduling_exists_exactly_for_work_that_will_be_retried() {
    let (_t, conn) = migrated("schedule");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET next_attempt_at = NULL WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "queued with no next attempt: {e}");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET state='delivered', terminal_at=1 WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "terminal with a next attempt: {e}");
}

#[test]
fn a_terminal_state_and_a_terminal_time_are_the_same_fact() {
    let (_t, conn) = migrated("terminal");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET state='delivered', next_attempt_at=NULL WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "terminal with no time: {e}");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET terminal_at=1 WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "a terminal time while queued: {e}");
}

#[test]
fn counters_cannot_go_negative() {
    let (_t, conn) = migrated("counters");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET attempts = -1 WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "{e}");

    let e = refused(
        &conn,
        &format!("UPDATE message SET size_bytes = -1 WHERE id = {m}"),
    );
    assert!(e.contains("CHECK"), "{e}");
}

// -------------------------------------------------------------- notification

#[test]
fn nothing_is_owed_for_a_delivery_that_succeeded() {
    let (_t, conn) = migrated("owed-success");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    let e = refused(
        &conn,
        &format!(
            "UPDATE delivery
                SET state='delivered', terminal_at=1, next_attempt_at=NULL, notification='owed'
              WHERE id = {d}"
        ),
    );
    assert!(e.contains("CHECK"), "a report owed for a success: {e}");
}

#[test]
fn a_report_cannot_exist_without_having_been_owed() {
    // The schema half of §9.2: `notification = 'enqueued'` and a `notified_by`
    // are one fact. A crash between the failure and the report leaves `owed`,
    // which the next pass picks up — but a row claiming a report with no
    // message behind it would look handled and never be retried.
    let (_t, conn) = migrated("enqueued");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");
    conn.execute(
        &format!(
            "UPDATE delivery SET state='failed', terminal_at=1, next_attempt_at=NULL,
                                 notification='owed' WHERE id = {d}"
        ),
        [],
    )
    .unwrap();

    let e = refused(
        &conn,
        &format!("UPDATE delivery SET notification='enqueued' WHERE id = {d}"),
    );
    assert!(e.contains("CHECK"), "enqueued with no report: {e}");

    // With the report, it is accepted.
    let dsn = message(&conn, "spool-dsn");
    conn.execute(
        &format!("UPDATE delivery SET notification='enqueued', notified_by={dsn} WHERE id = {d}"),
        [],
    )
    .unwrap();
}

// ---------------------------------------------------------------- recipients

#[test]
fn the_senders_recipients_survive_deduplication() {
    // Two aliases onto one destination: one delivery, two original recipients,
    // both mapped. A DSN has to name the address the sender wrote, and after
    // deduplication the delivery alone cannot say what that was.
    let (_t, conn) = migrated("recipients");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");

    for alias in ["hello@example.com", "sales@example.com"] {
        conn.execute(
            "INSERT INTO original_recipient(message_id, address) VALUES(?1, ?2)",
            rusqlite::params![m, alias],
        )
        .unwrap();
        let r = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO recipient_delivery(original_recipient_id, delivery_id) VALUES(?1, ?2)",
            rusqlite::params![r, d],
        )
        .unwrap();
    }

    let mut stmt = conn
        .prepare(
            "SELECT o.address FROM original_recipient o
               JOIN recipient_delivery rd ON rd.original_recipient_id = o.id
              WHERE rd.delivery_id = ?1 ORDER BY o.address",
        )
        .unwrap();
    let addresses: Vec<String> = stmt
        .query_map([d], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(addresses, vec!["hello@example.com", "sales@example.com"]);
}

#[test]
fn deleting_a_message_takes_its_queue_with_it() {
    // Retention deletes the whole record. A delivery outliving its message is a
    // row nothing can interpret and nothing will ever complete.
    let (_t, conn) = migrated("cascade");
    let m = message(&conn, "spool-1");
    let d = queued(&conn, m, "mailbox@provider.example");
    conn.execute(
        "INSERT INTO delivery_event(delivery_id, at, kind) VALUES(?1, 0, 'attempt')",
        [d],
    )
    .unwrap();

    conn.execute("DELETE FROM message WHERE id = ?1", [m])
        .unwrap();

    for table in [
        "delivery",
        "delivery_event",
        "original_recipient",
        "recipient_delivery",
    ] {
        let n: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "{table} outlived its message");
    }
}

// ------------------------------------------------------- the routing revision

fn revision(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT revision FROM routing_revision WHERE id = 1",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn routing_changes_advance_the_revision() {
    // Triggers rather than application code, so no writer can forget: a CLI
    // command, a repair by hand in sqlite3, or a restore replaying statements
    // all change what the daemon would serve.
    let (_t, conn) = migrated("revision");
    let before = revision(&conn);

    conn.execute(
        "INSERT INTO destination(local, domain) VALUES('me','example.net')",
        [],
    )
    .unwrap();
    let after_destination = revision(&conn);
    assert!(
        after_destination > before,
        "a destination did not advance it"
    );

    conn.execute(
        "INSERT INTO domain(name, status, inbound_enabled, default_destination_id,
                            created_at, updated_at)
         VALUES('example.com','active',1,1,0,0)",
        [],
    )
    .unwrap();
    let after_domain = revision(&conn);
    assert!(
        after_domain > after_destination,
        "a domain did not advance it"
    );

    conn.execute(
        "INSERT INTO alias(domain_id, pattern, kind, created_at) VALUES(1,'hello','forward',0)",
        [],
    )
    .unwrap();
    assert!(
        revision(&conn) > after_domain,
        "an alias did not advance it"
    );

    // Editing a destination changes where mail goes without touching any row
    // that names it, which is why it has triggers of its own.
    let before_edit = revision(&conn);
    conn.execute("UPDATE destination SET local = 'other'", [])
        .unwrap();
    assert!(
        revision(&conn) > before_edit,
        "editing a destination did not advance it"
    );

    // And a key: the snapshot and the signing keys are published together, so a
    // rotation has to reach the daemon the same way a routing change does.
    let before_key = revision(&conn);
    conn.execute(
        "INSERT INTO dkim_key(domain_id, selector, algorithm, public_key, private_key_path,
                              state, created_at)
         VALUES(1,'sel','rsa2048','AAAA','example.com/sel.key','active',0)",
        [],
    )
    .unwrap();
    assert!(revision(&conn) > before_key, "a key did not advance it");
}

#[test]
fn queue_activity_never_advances_the_routing_revision() {
    // The reason the counter exists. A busy relay commits delivery rows
    // continuously, and a doorbell that rang for those would have the detector
    // load and hash the routing tables once a second forever to conclude each
    // time that nothing routing-related had changed.
    let (_t, conn) = migrated("revision-queue");
    let m = message(&conn, "spool-1");
    let before = revision(&conn);

    let d = queued(&conn, m, "mailbox@provider.example");
    conn.execute(
        "INSERT INTO original_recipient(message_id, address) VALUES(?1,'hello@example.com')",
        [m],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO recipient_delivery(original_recipient_id, delivery_id) VALUES(1, ?1)",
        [d],
    )
    .unwrap();
    conn.execute(
        &format!(
            "UPDATE delivery SET state='delivering', claimed_by='w', claim_token='t',
                                 lease_expires_at=1, next_attempt_at=NULL WHERE id={d}"
        ),
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO delivery_event(delivery_id, at, kind) VALUES(?1, 0, 'attempt')",
        [d],
    )
    .unwrap();
    conn.execute("DELETE FROM message WHERE id = ?1", [m])
        .unwrap();

    assert_eq!(
        revision(&conn),
        before,
        "queue activity moved the routing revision"
    );
}

#[test]
fn the_revision_has_exactly_one_row() {
    // A counter with two rows is two counters, and the one a reader happens to
    // see becomes a matter of ordering.
    let (_t, conn) = migrated("revision-single");
    let e = refused(
        &conn,
        "INSERT INTO routing_revision(id, revision) VALUES(2, 0)",
    );
    assert!(e.contains("CHECK"), "{e}");
}
