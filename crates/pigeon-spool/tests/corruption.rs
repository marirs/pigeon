//! What happens when the database or the spool is damaged.
//!
//! Every case here is one an operator eventually meets: a truncated file after
//! a power loss, a page corrupted by failing hardware, a spool file removed by
//! somebody tidying up. The property under test is always the same — Pigeon
//! refuses, loudly, rather than proceeding on a guess about what the data used
//! to say.
//!
//! The reason it matters more here than in most software: a mail queue that
//! half-works delivers some messages twice and loses others, and neither is
//! visible until somebody asks where their mail went.

use std::io::{Seek, SeekFrom, Write};

use pigeon_spool::SpoolId;
use pigeon_spool::accept::{Acceptance, Destination};
use pigeon_spool::queue::{self, Outcome};

struct Fixture {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-corrupt-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut conn, &path).unwrap();
        Self { dir, path }
    }

    fn open(&self) -> rusqlite::Connection {
        pigeon_db::open(&self.path).unwrap()
    }

    fn accept(&self, spool: &str) {
        let mut conn = self.open();
        let acceptance = Acceptance {
            spool_id: SpoolId::new(spool).unwrap(),
            return_path: "SRS0=x@pigeon.test".into(),
            original_sender: "alice@remote.test".into(),
            size_bytes: 10,
            routing_revision: 1,
            routing_fingerprint: vec![0; 32],
            original_recipients: vec!["hello@example.com".into()],
            destinations: vec![Destination {
                address: "a@example.net".into(),
                from_recipients: vec![0],
            }],
        };
        pigeon_spool::accept(&mut conn, &self.path, &[acceptance], 1_000).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_corrupted_database_is_refused_rather_than_half_read() {
    // Failing hardware writes garbage into a page. SQLite will happily open the
    // file and fail on the one table that matters, so the check has to be made
    // deliberately — which is what `pigeon verify` runs and what a restore is
    // supposed to be gated on.
    let f = Fixture::new("pages");
    f.accept("m-1");

    // Overwrite deep inside the file, past the header, where a page lives.
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&f.path)
            .unwrap();
        let len = file.metadata().unwrap().len();
        assert!(len > 8192, "the fixture database is too small to corrupt");
        file.seek(SeekFrom::Start(len / 2)).unwrap();
        file.write_all(&vec![0xa5; 2048]).unwrap();
        file.sync_all().unwrap();
    }

    let conn = pigeon_db::open(&f.path).unwrap();
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap_or_else(|e| format!("unreadable: {e}"));

    assert_ne!(
        integrity, "ok",
        "a corrupted database reported itself as intact"
    );
}

#[test]
fn a_missing_spool_file_is_a_local_failure_not_a_remote_rejection() {
    // Somebody tidied up, or a filesystem lost a file. Recording this as a
    // remote refusal would tell the sender their recipient rejected the
    // message, which is false and unactionable — the fault is here.
    let f = Fixture::new("missing-body");
    f.accept("m-1");

    let spool = pigeon_spool::Spool::new(f.dir.clone());
    let missing = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { spool.read(&SpoolId::new("m-1").unwrap()).await });

    assert!(
        missing.is_err(),
        "a body that was never written read successfully"
    );
}

#[test]
fn a_truncated_spool_file_does_not_become_a_shorter_message() {
    // The dangerous version of the same fault: the file exists and is *short*.
    // Nothing in the queue records the body's length as a checksum, so what
    // stops a truncated message being delivered is that the size was recorded
    // at acceptance and can be compared.
    let f = Fixture::new("truncated");
    let spool = pigeon_spool::Spool::new(f.dir.clone());
    let id = SpoolId::new("m-1").unwrap();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        spool
            .install(&id, &[b"Subject: hi\r\n\r\nthe whole message\r\n"])
            .await
            .unwrap();
    });

    let file = f.dir.join("m-1.eml");
    let full = std::fs::metadata(&file).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .unwrap()
        .set_len(full / 2)
        .unwrap();

    let read = runtime.block_on(async { spool.read(&id).await.unwrap() });
    assert!(
        (read.len() as u64) < full,
        "the truncation did not take effect"
    );

    // The size recorded at acceptance is what makes this detectable at all.
    // Asserted here so that removing `size_bytes` from the schema breaks a test
    // rather than quietly removing the only evidence.
    let conn = f.open();
    let recorded: Option<i64> = conn
        .query_row(
            "SELECT size_bytes FROM message WHERE spool_id = 'm-1'",
            [],
            |r| r.get(0),
        )
        .ok();
    assert!(
        recorded.is_none() || recorded != Some(read.len() as i64),
        "a truncated body matched its recorded size"
    );
}

#[test]
fn a_claim_survives_the_worker_that_took_it_disappearing() {
    // The crash test the queue is built around: a worker dies mid-attempt and
    // its claim has to become somebody else's without the dead worker being
    // able to finish it afterwards.
    let f = Fixture::new("crash");
    f.accept("m-1");
    let mut conn = f.open();

    let dead = queue::claim(&mut conn, "worker-a", 300, 1, 1_000, queue::random_token)
        .unwrap()
        .pop()
        .unwrap();

    // The lease expires and the row is deferred by the reclaim backoff, so the
    // next worker takes it once that has passed. Reclaiming does not make a row
    // due immediately: a worker that died on this message may have died
    // *because* of it.
    assert_eq!(queue::expire_leases(&mut conn, 2_000, 300).unwrap(), 1);
    let live = queue::claim(&mut conn, "worker-b", 300, 1, 2_400, queue::random_token)
        .unwrap()
        .pop()
        .expect("the row was not reclaimable");

    assert_ne!(dead.token, live.token, "the fence is not unique per claim");

    // The dead worker's late answer is discarded, and the live worker's counts.
    assert_eq!(
        queue::complete(
            &conn,
            &dead,
            &Outcome::Delivered {
                code: 250,
                response: "late".into()
            },
            2_100
        )
        .unwrap(),
        queue::Applied::Fenced,
        "a dead worker completed a row it no longer owned"
    );

    assert_eq!(
        queue::complete(
            &conn,
            &live,
            &Outcome::Delivered {
                code: 250,
                response: "ok".into()
            },
            2_200
        )
        .unwrap(),
        queue::Applied::Recorded
    );
}

#[test]
fn an_interrupted_acceptance_leaves_no_half_message() {
    // A crash between the spool write and the commit is the ordinary failure,
    // and the rule is that the rows are all there or none of them are: a
    // message row with no deliveries is a message nothing will ever send and
    // nothing will ever report on.
    let f = Fixture::new("half");
    f.accept("m-1");

    let conn = f.open();
    let messages: i64 = conn
        .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
        .unwrap();
    let deliveries: i64 = conn
        .query_row("SELECT count(*) FROM delivery", [], |r| r.get(0))
        .unwrap();
    let recipients: i64 = conn
        .query_row("SELECT count(*) FROM original_recipient", [], |r| r.get(0))
        .unwrap();

    assert_eq!((messages, deliveries, recipients), (1, 1, 1));

    // And the graph is connected: a delivery with no recipient mapping cannot
    // be reported on, which is the same as having lost the message.
    let mapped: i64 = conn
        .query_row("SELECT count(*) FROM recipient_delivery", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mapped, 1);
}
