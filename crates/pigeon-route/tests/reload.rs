//! The change detector.
//!
//! `M1-RELOAD.md` §7. Two real connections throughout — one standing in for the
//! daemon, one for the CLI. Driving both sides through a single connection would
//! prove nothing, because the property under test is precisely that a *different*
//! connection's commits are seen.
//!
//! [`Watcher::tick`] is driven a step at a time rather than by running the loop
//! and sleeping. The racing case has to be deterministic: a commit placed
//! between the version read and the rebuild is the bug this exists to prevent,
//! and a timing-dependent test of that would be worse than none.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pigeon_db::repo::{self, Address, AliasKind};
use pigeon_route::{Router, Snapshot, Tick, Watcher};
use pigeon_types::Address as ParsedAddress;
use rusqlite::Connection;

struct Fixture {
    dir: PathBuf,
    /// The daemon's connection: long-lived, and the only one the watcher uses.
    daemon: Connection,
    /// Stands in for the CLI, in another process.
    writer: Connection,
    router: Router,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-reload-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");

        let mut setup = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut setup, &path).unwrap();
        drop(setup);

        let daemon = pigeon_db::open(&path).unwrap();
        let writer = pigeon_db::open(&path).unwrap();
        let router = Router::new(Snapshot::default());

        Self {
            dir,
            daemon,
            writer,
            router,
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.join("pigeon.db")
    }

    /// A domain that is carrying mail, created through the writer.
    fn seed(&self) {
        let me = Address::parse("me@example.net").unwrap();
        repo::add_domain(&self.writer, "example.com", Some(&me)).unwrap();
        self.writer
            .execute("UPDATE domain SET status = 'active'", [])
            .unwrap();
    }

    fn add_alias(&self, pattern: &str, to: &str) {
        let dest = Address::parse(to).unwrap();
        repo::add_alias(
            &self.writer,
            "example.com",
            pattern,
            AliasKind::Forward,
            std::slice::from_ref(&dest),
        )
        .unwrap();
    }

    fn routes_to(&self, address: &str) -> Option<String> {
        routes_to(&self.router, address)
    }

    fn tick(&self, w: &mut Watcher) -> Tick {
        w.tick(&self.daemon, &self.router)
    }
}

/// Where a router sends an address, if anywhere.
///
/// Free rather than a method, so a test can ask about a router it built itself
/// — which is now the only way to seed one.
fn routes_to(router: &Router, address: &str) -> Option<String> {
    let snap = router.for_transaction();
    let a = ParsedAddress::parse(address).unwrap();
    match snap.resolve(&a) {
        pigeon_route::Decision::Forward { destinations, .. } => Some(destinations[0].to_string()),
        _ => None,
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ------------------------------------------------------------ the basic loop

#[test]
fn the_first_tick_rebuilds_unconditionally() {
    // `seen` starts as `None`, which is what closes the window between
    // startup's build and the worker's first poll. A worker that adopted the
    // version it read at start would put any commit made in between inside its
    // baseline and never rebuild it.
    let f = Fixture::new("first");
    f.seed();
    f.add_alias("hello", "me@example.net");

    let mut w = Watcher::new();
    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "the first tick did not rebuild"
    );
    assert_eq!(
        f.routes_to("hello@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn a_commit_before_the_worker_starts_is_not_missed() {
    // The window the `None` baseline exists for, made explicit: startup builds,
    // *then* something commits, *then* the worker starts.
    let f = Fixture::new("startupwindow");
    f.seed();

    // Startup's build, on its own connection, seeded through `Router::new` —
    // which is how the daemon does it, and the only way to put a table into a
    // router. There is deliberately no public way to *replace* a serving one
    // outside the commit contract.
    let (snapshot, _reports, mut w) = pigeon_route::reload::initial(&f.daemon).unwrap();
    let router = Router::new(snapshot);
    assert_eq!(routes_to(&router, "hello@example.com"), None);

    // A commit that lands before the worker's first poll.
    f.add_alias("hello", "me@example.net");

    assert!(
        matches!(w.tick(&f.daemon, &router), Tick::Published { .. }),
        "a commit made between startup's build and the first poll was missed"
    );
    assert_eq!(
        routes_to(&router, "hello@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn an_unchanged_database_is_idle() {
    let f = Fixture::new("idle");
    f.seed();
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    for _ in 0..3 {
        assert_eq!(f.tick(&mut w), Tick::Idle, "an unchanged database rebuilt");
    }
}

#[test]
fn uncommitted_work_is_invisible() {
    let f = Fixture::new("uncommitted");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);

    let mut other = pigeon_db::open(&f.path()).unwrap();
    let tx = other.transaction().unwrap();
    repo::add_alias(&tx, "example.com", "ghost", AliasKind::Forward, &[]).unwrap();

    assert_eq!(
        f.tick(&mut w),
        Tick::Idle,
        "an open write transaction was treated as a change"
    );
    assert_eq!(f.routes_to("ghost@example.com"), None);

    tx.commit().unwrap();
    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "the commit was not picked up"
    );
    assert_eq!(
        f.routes_to("ghost@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn rapid_commits_coalesce_to_the_latest() {
    // Several commits between polls produce one version change and one rebuild
    // from the latest state. The contract is that the latest committed state is
    // eventually published, not that every intermediate one is.
    let f = Fixture::new("rapid");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);

    for i in 0..10 {
        f.add_alias(&format!("a{i}"), "me@example.net");
    }

    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));
    for i in 0..10 {
        assert_eq!(
            f.routes_to(&format!("a{i}@example.com")).as_deref(),
            Some("me@example.net"),
            "a{i} was lost in a burst"
        );
    }
    assert_eq!(f.tick(&mut w), Tick::Idle);
}

// -------------------------------------------------- the doorbell, not a diff

#[test]
fn a_commit_that_touches_no_routing_publishes_nothing() {
    // `data_version` moves on *every* commit, and from Milestone 3 the queue
    // shares this database and commits continuously. Without the fingerprint,
    // every queue write would rebuild, republish and log a reload.
    let f = Fixture::new("unrelated");
    f.seed();
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    f.writer
        .execute(
            "INSERT INTO setting (key, value, updated_at) VALUES ('x', 'y', 0)",
            [],
        )
        .unwrap();

    assert_eq!(
        f.tick(&mut w),
        Tick::Unrelated,
        "a non-routing commit was published as a reload"
    );
    // And it is consumed, so it does not re-trigger.
    assert_eq!(f.tick(&mut w), Tick::Idle);
}

#[test]
fn a_change_that_reverts_to_the_published_state_publishes_nothing() {
    // Two commits whose net effect is nothing. The fingerprint compares state,
    // not history.
    let f = Fixture::new("revert");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    repo::remove_alias(&f.writer, "example.com", "hello").unwrap();
    f.add_alias("hello", "me@example.net");

    assert_eq!(f.tick(&mut w), Tick::Unrelated);
}

// ------------------------------------------------------------- the ordering

#[test]
fn a_commit_racing_snapshot_construction_is_not_lost() {
    // The bug the ordering rule exists to prevent, produced deliberately rather
    // than by timing.
    //
    // The version is read at the top of a tick. A commit lands *inside* that
    // window — after the version, before the rows. The recorded version must be
    // the earlier one, so the next tick still finds work; a version read after
    // the rows would already include this commit and consume it unbuilt.
    let f = Fixture::new("race");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);

    // A change already in flight, so the tick gets past its version check and
    // reaches the window at all.
    f.add_alias("first", "me@example.net");

    let mut ran = false;
    let tick = w.tick_with(&f.daemon, &f.router, || {
        // Inside the window: the rows have been read, and the version about to
        // be recorded was read before them. A version read *here* would already
        // include this commit, and recording it would consume a change that was
        // never built.
        f.add_alias("racer", "me@example.net");
        ran = true;
    });
    assert!(ran, "the hook did not run");
    assert!(matches!(tick, Tick::Published { .. }), "{tick:?}");

    // The commit made inside the window is not in the snapshot just published.
    assert_eq!(
        f.routes_to("racer@example.com"),
        None,
        "the test did not actually open the window it is testing"
    );

    // And it must still be pending: the next tick builds it.
    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "a commit made after the rows were read was consumed without being built"
    );
    assert_eq!(
        f.routes_to("racer@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn a_commit_immediately_after_a_rebuild_is_not_lost() {
    let f = Fixture::new("after");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);

    f.add_alias("a", "me@example.net");
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    f.add_alias("b", "me@example.net");
    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "a commit made immediately after a rebuild was consumed without being built"
    );
    assert_eq!(
        f.routes_to("b@example.com").as_deref(),
        Some("me@example.net")
    );
}

// ------------------------------------------------------------------ failure

/// Break the configuration in a way only the snapshot can see.
///
/// An alias inheriting a default the domain does not have: every row is legal
/// and the configuration as a whole cannot be served.
fn make_invalid(f: &Fixture) {
    repo::add_alias(&f.writer, "example.com", "orphan", AliasKind::Forward, &[]).unwrap();
    repo::set_default_destination(&f.writer, "example.com", None).unwrap();
}

#[test]
fn an_invalid_configuration_retains_the_last_good_table() {
    let f = Fixture::new("invalid");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    make_invalid(&f);

    assert!(matches!(f.tick(&mut w), Tick::Invalid { .. }));
    assert_eq!(
        f.routes_to("hello@example.com").as_deref(),
        Some("me@example.net"),
        "an invalid configuration replaced a working routing table"
    );
}

#[test]
fn an_invalid_version_is_not_consumed_and_logs_once() {
    let f = Fixture::new("logonce");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);
    make_invalid(&f);

    // Twenty polls against a configuration that will never build.
    let mut rebuilt = 0;
    let mut logged = 0;
    let mut throttled = 0;
    for _ in 0..20 {
        match f.tick(&mut w) {
            Tick::Invalid { logged: l, .. } => {
                rebuilt += 1;
                if l {
                    logged += 1;
                }
            }
            Tick::Backoff => throttled += 1,
            other => panic!("unexpected {other:?}"),
        }
    }

    // Logged once for the version, however many times it is retried. A
    // configuration that will never build must not fill the log.
    assert_eq!(logged, 1, "an unchanging failure logged {logged} times");

    // Retried, because the version is never consumed — a transient failure that
    // advanced `seen` would swallow a real change. But throttled, because this
    // one is not transient.
    assert!(
        rebuilt >= 2,
        "a failed version was consumed and never retried"
    );
    assert!(
        rebuilt <= 6,
        "the rebuild was not throttled: {rebuilt} of 20 polls rebuilt"
    );
    assert!(throttled > 0, "nothing was throttled");

    // And every one of those 20 polls happened: throttling the rebuild must
    // never throttle detection.
    assert_eq!(rebuilt + throttled, 20);
}

#[test]
fn a_fix_is_picked_up_promptly_despite_the_backoff() {
    // The backoff throttles rebuilding, never polling. A fix committed during a
    // backoff window is the commit that most deserves prompt pickup, and
    // suspending the poll would make it wait out the whole delay.
    let f = Fixture::new("recovery");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    f.tick(&mut w);

    make_invalid(&f);
    assert!(matches!(f.tick(&mut w), Tick::Invalid { .. }));

    // The fix, committed while the throttle is still armed — not after it has
    // been spent. Ticking first would let the backoff lapse and the test would
    // pass whether or not a new version cancels it.
    let me = Address::parse("me@example.net").unwrap();
    repo::set_default_destination(&f.writer, "example.com", Some(&me)).unwrap();

    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "a fix waited out the backoff instead of cancelling it"
    );
    assert_eq!(
        f.routes_to("orphan@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn a_reconnect_rebuilds_unconditionally() {
    // `data_version` counts changes *this connection* has observed, so a fresh
    // connection's value has no relationship to the old one's. Adopting it
    // would skip every change until the new counter caught up.
    //
    // Asserted on the state rather than on an outcome: a test that commits a
    // change first and watches it arrive passes for the wrong reason whenever
    // the fresh connection's counter happens to differ from the recorded one,
    // which is most of the time.
    let f = Fixture::new("reconnect");
    f.seed();
    let mut w = Watcher::new();
    f.tick(&mut w);
    assert!(w.has_baseline(), "a successful tick recorded no baseline");

    w.reconnected();
    assert!(
        !w.has_baseline(),
        "a reconnect kept a baseline from the old connection, whose version counter \
         has no meaning on the new one"
    );

    // And the next tick really does rebuild rather than idling.
    f.add_alias("hello", "me@example.net");
    let fresh = pigeon_db::open(&f.path()).unwrap();
    assert!(matches!(w.tick(&fresh, &f.router), Tick::Published { .. }));
    assert_eq!(
        f.routes_to("hello@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn startup_hands_over_no_baseline() {
    // The same property at the other end: `initial` records the fingerprint it
    // published but deliberately not the version, so the worker's first tick
    // rebuilds and the window between startup and the worker cannot hide a
    // commit.
    let f = Fixture::new("initialbaseline");
    f.seed();
    let (_snapshot, _reports, w) = pigeon_route::reload::initial(&f.daemon).unwrap();
    assert!(
        !w.has_baseline(),
        "startup handed the worker a baseline, which closes the window it must leave open"
    );
}

#[test]
fn a_transient_read_failure_does_not_consume_the_version() {
    // A failure to *read* is not a failure of the configuration. Advancing the
    // version here would mean a locked database or an I/O blip permanently
    // swallowed a real change.
    let f = Fixture::new("transient");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    // Make the read fail without making the configuration invalid: the table
    // the loader needs is gone, which is an error from SQLite rather than a
    // rule the snapshot refuses.
    f.writer
        .execute_batch("ALTER TABLE alias RENAME TO alias_hidden")
        .unwrap();

    let before = w.baseline();
    assert!(
        matches!(f.tick(&mut w), Tick::Transient { .. }),
        "a read failure was reported as something else"
    );
    // Asserted on the state, because the behavioural version needs a later
    // commit to observe — and that commit moves the version, which is exactly
    // what would hide an advanced baseline.
    assert_eq!(
        w.baseline(),
        before,
        "a transient read failure consumed the pending version"
    );
    assert_eq!(
        f.routes_to("hello@example.com").as_deref(),
        Some("me@example.net"),
        "a read failure discarded the working routing table"
    );

    // Put it back. The change must still be pending — if the transient failure
    // had consumed the version, this would idle forever.
    f.writer
        .execute_batch("ALTER TABLE alias_hidden RENAME TO alias")
        .unwrap();
    f.add_alias("after", "me@example.net");
    assert!(
        matches!(f.tick(&mut w), Tick::Published { .. }),
        "the change pending across a transient failure was lost"
    );
    assert_eq!(
        f.routes_to("after@example.com").as_deref(),
        Some("me@example.net")
    );
}

// -------------------------------------------------------------- pinning

#[test]
fn a_transaction_keeps_its_snapshot_across_a_reload() {
    // Already true of the router, and re-asserted against a publication that
    // came from the watcher rather than from a test: a message accepted under
    // one configuration is delivered under the same one.
    let f = Fixture::new("pinning");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    f.tick(&mut w);

    // MAIL FROM: the transaction takes its handle.
    let pinned = f.router.for_transaction();

    // The operator removes the recipient, and the watcher publishes.
    repo::remove_alias(&f.writer, "example.com", "hello").unwrap();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    let a = ParsedAddress::parse("hello@example.com").unwrap();
    assert!(
        matches!(pinned.resolve(&a), pigeon_route::Decision::Forward { .. }),
        "a reload changed the routing table underneath an open transaction"
    );
    // And the next transaction sees the new one.
    assert_eq!(f.routes_to("hello@example.com"), None);
}

// --------------------------------------------------- review findings, pinned

#[test]
fn the_load_runs_inside_a_read_transaction() {
    // `load` issues a query for domains, then one per domain for its aliases,
    // then one per alias for its destinations. Without a transaction a commit
    // landing partway through yields a configuration assembled from two states
    // of the database — a hybrid nobody committed, published as though somebody
    // had.
    //
    // Asserted deterministically rather than by racing a writer: SQLite refuses
    // to nest transactions, so a tick on a connection that is *already* inside
    // one must fail. If the load opened no transaction of its own, it would
    // happily succeed.
    let f = Fixture::new("readtxn");
    f.seed();
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));
    f.add_alias("hello", "me@example.net");

    let outer = f.daemon.unchecked_transaction().unwrap();
    let tick = w.tick(&f.daemon, &f.router);
    drop(outer);

    match tick {
        Tick::Transient { message } => assert!(
            message.contains("transaction"),
            "failed for the wrong reason: {message}"
        ),
        other => panic!("the load did not open a transaction of its own: {other:?}"),
    }
}

#[test]
fn a_status_this_build_cannot_read_is_invalid_not_transient() {
    // A row this build cannot interpret reads the same way on every retry.
    // Treating it as transient means retrying every second and logging at
    // debug, when what an operator needs is one warning and a backoff.
    let f = Fixture::new("unknownstatus");
    f.seed();
    f.add_alias("hello", "me@example.net");
    let mut w = Watcher::new();
    assert!(matches!(f.tick(&mut w), Tick::Published { .. }));

    // Written the way a restore or a newer build would leave it: the CHECK
    // constraint is what normally prevents this, so it is removed first.
    f.writer
        .execute_batch(
            "PRAGMA writable_schema=ON;
             UPDATE sqlite_master SET sql = replace(sql,
               \"CHECK (status IN ('new','pending_dns','ready','active','error'))\", '')
             WHERE type='table' AND name='domain';
             PRAGMA writable_schema=OFF;",
        )
        .unwrap();
    let reopened = pigeon_db::open(&f.path()).unwrap();
    reopened
        .execute("UPDATE domain SET status = 'from_the_future'", [])
        .unwrap();

    match f.tick(&mut w) {
        Tick::Invalid { logged, .. } => assert!(logged, "the first failure did not log"),
        other => panic!("an unreadable status was not treated as invalid: {other:?}"),
    }

    // And it backs off rather than rebuilding every poll.
    assert_eq!(f.tick(&mut w), Tick::Backoff);

    // The last good table is still serving.
    assert_eq!(
        f.routes_to("hello@example.com").as_deref(),
        Some("me@example.net")
    );
}
