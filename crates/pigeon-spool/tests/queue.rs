//! Claiming, fencing, and giving up.
//!
//! The rule under test throughout is that a claim is only good while it is
//! still the claim: a worker whose lease expired must be unable to overwrite
//! the result of the worker that replaced it.

use pigeon_spool::SpoolId;
use pigeon_spool::accept::{Acceptance, Destination};
use pigeon_spool::queue::{self, Applied, Outcome};
use rusqlite::Connection;

const LEASE: i64 = 300;

/// The production generator. Used here rather than a counter because a counter
/// would have to be shared between every claim in a test to be unique, and a
/// test that accidentally reuses a token passes while fencing is broken —
/// which is exactly what happened when this file first used one.
fn tokens() -> fn() -> String {
    queue::random_token
}

struct Fixture {
    _dir: std::path::PathBuf,
    path: std::path::PathBuf,
    conn: Connection,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-queue-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut conn, &path).unwrap();
        Self {
            _dir: dir,
            path,
            conn,
        }
    }

    fn accept(&mut self, spool: &str, destinations: &[&str], received_at: i64, return_path: &str) {
        let acceptance = Acceptance {
            spool_id: SpoolId::new(spool).unwrap(),
            return_path: return_path.into(),
            original_sender: "alice@remote.test".into(),
            size_bytes: 10,
            routing_revision: 1,
            routing_fingerprint: vec![0; 32],
            original_recipients: vec!["hello@example.com".into()],
            destinations: destinations
                .iter()
                .map(|d| Destination {
                    address: (*d).to_string(),
                    from_recipients: vec![0],
                })
                .collect(),
        };
        pigeon_spool::accept(&mut self.conn, &self.path, &[acceptance], received_at).unwrap();
    }

    fn state(&self, delivery_id: i64) -> String {
        queue::state_of(&self.conn, delivery_id).unwrap().unwrap()
    }

    fn column<T: rusqlite::types::FromSql>(&self, delivery_id: i64, name: &str) -> T {
        self.conn
            .query_row(
                &format!("SELECT {name} FROM delivery WHERE id = ?1"),
                [delivery_id],
                |r| r.get(0),
            )
            .unwrap()
    }
}

// ------------------------------------------------------------------ claiming

#[test]
fn claiming_takes_due_work_and_counts_the_claim() {
    let mut f = Fixture::new("claim");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");

    let claims = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens()).unwrap();
    assert_eq!(claims.len(), 1);
    let c = &claims[0];
    assert_eq!(c.destination, "a@provider.example");
    assert_eq!(c.return_path, "SRS0=x@pigeon.test");
    assert_eq!(c.attempts, 1, "the claim was not counted");
    assert_eq!(f.state(c.delivery_id), "delivering");

    // And it is no longer due, so a second worker gets nothing.
    let none = queue::claim(&mut f.conn, "worker-2", LEASE, 10, 100, tokens()).unwrap();
    assert!(none.is_empty(), "a claimed delivery was claimed twice");
}

#[test]
fn work_that_is_not_due_yet_is_left_alone() {
    let mut f = Fixture::new("not-due");
    f.accept(
        "msg-a",
        &["a@provider.example"],
        1_000,
        "SRS0=x@pigeon.test",
    );

    let claims = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 999, tokens()).unwrap();
    assert!(claims.is_empty(), "claimed a delivery before it was due");
}

#[test]
fn a_terminal_delivery_is_never_claimed() {
    let mut f = Fixture::new("terminal");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    let claims = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens()).unwrap();
    queue::complete(
        &f.conn,
        &claims[0],
        &Outcome::Delivered {
            code: 250,
            response: "Ok".into(),
        },
        200,
    )
    .unwrap();

    let again = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 10_000, tokens()).unwrap();
    assert!(again.is_empty(), "a delivered message was claimed again");
}

// ------------------------------------------------------------------- fencing

#[test]
fn a_worker_whose_lease_expired_cannot_overwrite_its_replacement() {
    // The rule the whole module exists for. Worker one is slow; its lease
    // expires; worker two claims the row and delivers. Worker one then finishes
    // and tries to record a failure — which must not land, because the attempt
    // it describes is not the one that owns the row.
    let mut f = Fixture::new("fence");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");

    let first = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens()).unwrap();
    let first = first.into_iter().next().unwrap();

    // The lease runs out and the row is reclaimed.
    let reclaimed = queue::expire_leases(&mut f.conn, 100 + LEASE + 1, 0).unwrap();
    assert_eq!(reclaimed, 1);

    let second = queue::claim(
        &mut f.conn,
        "worker-2",
        LEASE,
        10,
        100 + LEASE + 1,
        tokens(),
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();
    assert_ne!(first.token, second.token, "the claim token was reused");

    // Worker two succeeds.
    assert_eq!(
        queue::complete(
            &f.conn,
            &second,
            &Outcome::Delivered {
                code: 250,
                response: "Ok".into()
            },
            500,
        )
        .unwrap(),
        Applied::Recorded
    );

    // Worker one, still running, reports its own failure.
    assert_eq!(
        queue::complete(
            &f.conn,
            &first,
            &Outcome::Failed {
                code: 550,
                response: "No such user".into()
            },
            501,
        )
        .unwrap(),
        Applied::Fenced,
        "an expired claim overwrote its replacement's result"
    );

    assert_eq!(f.state(second.delivery_id), "delivered");
    let code: i64 = f.column(second.delivery_id, "last_code");
    assert_eq!(code, 250, "the fenced worker's response was recorded");
}

#[test]
fn the_same_worker_name_does_not_make_a_stale_claim_valid() {
    // Identity is reusable — the same host, the same name after a restart — so
    // a check on `claimed_by` alone would let a previous attempt by the same
    // worker record a result for the current one.
    let mut f = Fixture::new("same-name");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");

    let first = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    queue::expire_leases(&mut f.conn, 100 + LEASE + 1, 0).unwrap();
    let second = queue::claim(
        &mut f.conn,
        "worker-1",
        LEASE,
        10,
        100 + LEASE + 1,
        tokens(),
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();

    assert_eq!(first.delivery_id, second.delivery_id);
    assert_eq!(
        queue::complete(
            &f.conn,
            &first,
            &Outcome::Delivered {
                code: 250,
                response: "Ok".into()
            },
            500
        )
        .unwrap(),
        Applied::Fenced,
        "a stale claim from the same worker was accepted"
    );
    assert_eq!(f.state(second.delivery_id), "delivering");
}

#[test]
fn a_reclaimed_delivery_is_due_again_and_keeps_its_attempt_count() {
    let mut f = Fixture::new("reclaim");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");

    let first = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    queue::expire_leases(&mut f.conn, 100 + LEASE + 1, 0).unwrap();

    assert_eq!(f.state(first.delivery_id), "deferred");
    let second = queue::claim(
        &mut f.conn,
        "worker-2",
        LEASE,
        10,
        100 + LEASE + 1,
        tokens(),
    )
    .unwrap()
    .into_iter()
    .next()
    .unwrap();
    assert_eq!(
        second.attempts, 2,
        "a reclaimed delivery forgot it had been tried"
    );
}

// --------------------------------------------------------------- completion

#[test]
fn a_deferral_schedules_the_next_attempt_and_owes_nothing() {
    let mut f = Fixture::new("defer");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    let c = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    queue::complete(
        &f.conn,
        &c,
        &Outcome::Deferred {
            code: Some(451),
            response: "later".into(),
            next_attempt_at: 400,
        },
        200,
    )
    .unwrap();

    assert_eq!(f.state(c.delivery_id), "deferred");
    assert_eq!(f.column::<i64>(c.delivery_id, "next_attempt_at"), 400);
    assert_eq!(f.column::<String>(c.delivery_id, "notification"), "none");
}

#[test]
fn a_permanent_failure_owes_a_report_unless_the_sender_is_null() {
    let mut f = Fixture::new("owed");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    // A bounce: no return path, so no report is owed for its failure.
    f.accept("msg-b", &["b@provider.example"], 100, "");

    let claims = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens()).unwrap();
    assert_eq!(claims.len(), 2);

    for c in &claims {
        queue::complete(
            &f.conn,
            c,
            &Outcome::Failed {
                code: 550,
                response: "No such user".into(),
            },
            200,
        )
        .unwrap();
    }

    let owed: Vec<(String, String)> = {
        let mut stmt = f
            .conn
            .prepare("SELECT d.destination, d.notification FROM delivery d ORDER BY d.destination")
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(
        owed,
        vec![
            ("a@provider.example".to_string(), "owed".to_string()),
            ("b@provider.example".to_string(), "none".to_string()),
        ],
        "a bounce that failed owes a report, or a real failure owes none"
    );
}

#[test]
fn every_completion_is_recorded_as_an_event() {
    let mut f = Fixture::new("events");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    let c = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    queue::complete(
        &f.conn,
        &c,
        &Outcome::Deferred {
            code: Some(451),
            response: "later".into(),
            next_attempt_at: 400,
        },
        200,
    )
    .unwrap();

    let kinds: Vec<String> = {
        let mut stmt = f
            .conn
            .prepare("SELECT kind FROM delivery_event WHERE delivery_id = ?1")
            .unwrap();
        stmt.query_map([c.delivery_id], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(kinds, vec!["defer"]);
}

#[test]
fn a_fenced_completion_records_no_event() {
    // The log is what an operator reads to understand what happened. An
    // attempt whose result was discarded did not happen, as far as the row is
    // concerned, and writing an event for it would describe a state change
    // that never occurred.
    let mut f = Fixture::new("fenced-event");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    let stale = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    queue::expire_leases(&mut f.conn, 100 + LEASE + 1, 0).unwrap();

    queue::complete(
        &f.conn,
        &stale,
        &Outcome::Delivered {
            code: 250,
            response: "Ok".into(),
        },
        500,
    )
    .unwrap();

    let n: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM delivery_event WHERE delivery_id = ?1",
            [stale.delivery_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "a fenced completion wrote an event");
}

// ------------------------------------------------------------------- expiry

#[test]
fn giving_up_is_governed_by_age_not_by_attempts() {
    // A run of local crashes says nothing about the destination. If attempts
    // decided, Pigeon crashing repeatedly would manufacture a permanent
    // delivery failure and bounce mail that was never refused by anybody.
    let horizon = 5 * 24 * 60 * 60;
    let mut f = Fixture::new("age");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");

    // Twenty claims and twenty crashes: the attempt count climbs and nothing
    // becomes terminal.
    // Time advances past each lease, or the reclaimed row would not be due
    // again and the loop would claim nothing after the first pass.
    let mut now = 100;
    for _ in 0..20 {
        let claimed = queue::claim(&mut f.conn, "worker-1", LEASE, 10, now, tokens()).unwrap();
        assert_eq!(claimed.len(), 1, "nothing was due at {now}");
        now += LEASE + 1;
        queue::expire_leases(&mut f.conn, now, 0).unwrap();
    }
    let id: i64 = f
        .conn
        .query_row("SELECT id FROM delivery", [], |r| r.get(0))
        .unwrap();
    assert!(f.column::<i64>(id, "attempts") >= 20);
    assert_eq!(f.state(id), "deferred", "attempts alone ended a delivery");

    // Nothing expires before the horizon.
    assert_eq!(
        queue::expire_old(&f.conn, horizon, 100 + horizon).unwrap(),
        0
    );

    // And after it, one does.
    assert_eq!(
        queue::expire_old(&f.conn, horizon, 101 + horizon).unwrap(),
        1
    );
    assert_eq!(f.state(id), "expired");
    assert_eq!(f.column::<String>(id, "notification"), "owed");
}

#[test]
fn expiry_owes_nothing_for_a_message_with_no_return_path() {
    let horizon = 5 * 24 * 60 * 60;
    let mut f = Fixture::new("age-bounce");
    f.accept("msg-a", &["a@provider.example"], 100, "");

    assert_eq!(
        queue::expire_old(&f.conn, horizon, 101 + horizon).unwrap(),
        1
    );
    let id: i64 = f
        .conn
        .query_row("SELECT id FROM delivery", [], |r| r.get(0))
        .unwrap();
    assert_eq!(f.column::<String>(id, "notification"), "none");
}

#[test]
fn a_delivery_in_flight_is_not_expired_underneath_its_worker() {
    // Expiry acts on work that is waiting, not on work in progress: taking a
    // row away from a live attempt would make its result arrive as a fenced
    // update and lose the outcome the remote actually gave.
    let horizon = 5 * 24 * 60 * 60;
    let mut f = Fixture::new("age-inflight");
    f.accept("msg-a", &["a@provider.example"], 100, "SRS0=x@pigeon.test");
    let c = queue::claim(&mut f.conn, "worker-1", LEASE, 10, 100, tokens())
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    assert_eq!(
        queue::expire_old(&f.conn, horizon, 101 + horizon).unwrap(),
        0,
        "expiry took a delivery away from a running attempt"
    );
    assert_eq!(f.state(c.delivery_id), "delivering");
}

// ------------------------------------------------------------------- leases

#[test]
fn the_default_lease_outlasts_the_delivery_deadline() {
    // A lease that expires while its attempt is still running has the row
    // reclaimed underneath a live worker: the replacement connects to the same
    // destination, the first worker's result is fenced, and a message that was
    // delivered once is delivered twice with the remote's real answer thrown
    // away.
    //
    // 1800s is `TOTAL_FORWARD_BUDGET` in the daemon. The check is a function so
    // startup can run it against whatever the two are actually configured to
    // be, rather than trusting that a comment stayed true.
    queue::assert_lease_exceeds_deadline(queue::DEFAULT_LEASE_SECONDS, 1800);
}

#[test]
#[should_panic(expected = "does not outlast")]
fn a_lease_shorter_than_the_deadline_is_refused() {
    queue::assert_lease_exceeds_deadline(60, 1800);
}

// ------------------------------------------------------- retention of records

/// Settle a message: deliver every destination, then mark its body released.
fn settle(f: &mut Fixture, at: i64) {
    let claims = queue::claim(&mut f.conn, "w", LEASE, 10, at, tokens()).unwrap();
    for claim in claims {
        queue::complete(
            &f.conn,
            &claim,
            &Outcome::Delivered {
                code: 250,
                response: "ok".into(),
            },
            at,
        )
        .unwrap();
    }
    let ids: Vec<i64> = f
        .conn
        .prepare("SELECT id FROM message")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    for id in ids {
        pigeon_spool::dsn::mark_body_released(&f.conn, id, at).unwrap();
    }
}

fn messages(f: &Fixture) -> i64 {
    f.conn
        .query_row("SELECT count(*) FROM message", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_settled_record_outlives_its_body_and_is_then_collected() {
    // The two lifetimes of §8. The body goes when Pigeon is finished with the
    // message; the record of what happened outlives it, because "what happened
    // to this message?" is asked days later.
    let mut f = Fixture::new("retain");
    f.accept("m-1", &["a@example.net"], 1_000, "SRS0=x@pigeon.test");
    settle(&mut f, 2_000);

    // Inside the window: nothing is collected, however settled.
    assert_eq!(
        queue::expire_metadata(&f.conn, 100, 2_050).unwrap(),
        0,
        "a record was collected before its window elapsed"
    );
    assert_eq!(messages(&f), 1);

    // At the boundary the record still stands: strictly older, so a message
    // gets the whole window.
    assert_eq!(queue::expire_metadata(&f.conn, 100, 2_100).unwrap(), 0);

    assert_eq!(queue::expire_metadata(&f.conn, 100, 2_101).unwrap(), 1);
    assert_eq!(messages(&f), 0);

    // And nothing dangles: the recipients, deliveries and events go with it.
    for table in [
        "original_recipient",
        "delivery",
        "recipient_delivery",
        "delivery_event",
    ] {
        let n: i64 = f
            .conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "{table} rows outlived the message they describe");
    }
}

#[test]
fn a_message_that_is_not_settled_is_never_collected() {
    // Age alone is not the rule. A message still being delivered, or still
    // owing a report, has an outcome nobody has been told yet — collecting it
    // would delete the only record of an obligation Pigeon has not discharged.
    let mut f = Fixture::new("retain-unsettled");
    f.accept("m-1", &["a@example.net"], 1_000, "SRS0=x@pigeon.test");

    // In flight, and ancient.
    assert_eq!(queue::expire_metadata(&f.conn, 100, 9_000_000).unwrap(), 0);
    assert_eq!(messages(&f), 1);

    // Failed with a report owed, body marked released anyway — the guard does
    // not rely on `body_deleted_at` being written correctly.
    let claim = queue::claim(&mut f.conn, "w", LEASE, 1, 2_000, tokens())
        .unwrap()
        .pop()
        .unwrap();
    queue::complete(
        &f.conn,
        &claim,
        &Outcome::Failed {
            code: 550,
            response: "no such user".into(),
        },
        2_000,
    )
    .unwrap();
    pigeon_spool::dsn::mark_body_released(&f.conn, 1, 2_000).unwrap();

    assert_eq!(
        queue::expire_metadata(&f.conn, 100, 9_000_000).unwrap(),
        0,
        "a message still owing a report was collected"
    );
}

#[test]
fn a_record_whose_body_is_still_on_disk_is_not_collected() {
    // The window is measured from the body's release, so a message whose body
    // was never released has no window yet — however terminal its deliveries
    // are. Collecting it would leave the body on disk with nothing pointing at
    // it, and the sweep would then remove it as an orphan: the record and the
    // message would disappear in two separate acts nobody ordered.
    let mut f = Fixture::new("retain-unreleased");
    f.accept("m-1", &["a@example.net"], 1_000, "SRS0=x@pigeon.test");

    let claim = queue::claim(&mut f.conn, "w", LEASE, 1, 2_000, tokens())
        .unwrap()
        .pop()
        .unwrap();
    queue::complete(
        &f.conn,
        &claim,
        &Outcome::Delivered {
            code: 250,
            response: "ok".into(),
        },
        2_000,
    )
    .unwrap();

    // Settled, ancient, and its body has not been released.
    assert_eq!(
        queue::expire_metadata(&f.conn, 100, 9_000_000).unwrap(),
        0,
        "a record was collected while its body was still on disk"
    );
}

#[test]
fn a_report_outlives_the_failure_it_explains() {
    // The notification outcome has to stay explainable. Collecting the DSN
    // while the failure still points at it would leave `notification =
    // 'enqueued'` with nothing to name, which is the one question retention
    // exists to answer: not just "did this fail?" but "was the sender told?".
    let mut f = Fixture::new("retain-report");
    f.accept("m-1", &["a@example.net"], 1_000, "SRS0=x@pigeon.test");

    let claim = queue::claim(&mut f.conn, "w", LEASE, 1, 2_000, tokens())
        .unwrap()
        .pop()
        .unwrap();
    queue::complete(
        &f.conn,
        &claim,
        &Outcome::Failed {
            code: 550,
            response: "no such user".into(),
        },
        2_000,
    )
    .unwrap();

    // The DSN, and the failure now pointing at it.
    f.accept("m-2", &["alice@remote.test"], 2_000, "");
    let report_id: i64 = f
        .conn
        .query_row("SELECT id FROM message WHERE spool_id = 'm-2'", [], |r| {
            r.get(0)
        })
        .unwrap();
    f.conn
        .execute(
            "UPDATE delivery SET notification = 'enqueued', notified_by = ?1
              WHERE message_id = (SELECT id FROM message WHERE spool_id = 'm-1')",
            [report_id],
        )
        .unwrap();

    // Both settled and both far past the window.
    settle(&mut f, 3_000);
    assert_eq!(messages(&f), 2);

    // The failure's record goes; the report it points at stays, because until
    // that moment the report is what explains the failure's notification.
    assert_eq!(queue::expire_metadata(&f.conn, 100, 9_000).unwrap(), 1);
    let left: String = f
        .conn
        .query_row("SELECT spool_id FROM message", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, "m-2", "the report was collected before the failure");

    // Once nothing points at it, it is collectable in its own right.
    assert_eq!(queue::expire_metadata(&f.conn, 100, 9_000).unwrap(), 1);
    assert_eq!(messages(&f), 0);
}
