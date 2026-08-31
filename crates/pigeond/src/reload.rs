//! Running the change detector, and supervising it.
//!
//! The detector itself is `pigeon_route::reload`. What is here is the loop
//! around it, the shutdown path, and — the part that is easy to get wrong — the
//! supervision that reports a worker which stopped.

use std::path::PathBuf;
use std::sync::Arc;

use pigeon_route::{Publish, Tick, Watcher};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How long shutdown waits for the worker.
///
/// The worker sleeps for a poll interval between iterations, so it can take up
/// to that long to notice the signal. This is comfortably more.
const SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Signals the worker to stop, without owning its join handle.
pub struct Stopper {
    stop: watch::Sender<bool>,
}

impl Stopper {
    fn signal(&self) {
        let _ = self.stop.send(true);
    }

    /// Signal, then wait for the worker to actually end.
    ///
    /// Signals **and joins**, through the supervisor: joining is what makes
    /// shutdown deterministic — a signalled-but-unjoined worker may still be
    /// mid-rebuild, and a process that exits underneath it leaves "did the last
    /// reload finish?" unanswerable. It is also what closes the worker's SQLite
    /// connection at a known point rather than at process teardown.
    ///
    /// It is *not* about WAL recovery: an abandoned reader leaves none, because
    /// process exit releases its locks. What a live reader does is hold back
    /// checkpointing, and that stops mattering when the process is ending.
    ///
    /// Bounded. A worker that will not stop is reported and abandoned rather
    /// than hanging the shutdown, because the alternative is a daemon that
    /// cannot be stopped without `SIGKILL`.
    pub async fn stop_and_join(self, supervisor: JoinHandle<()>) {
        self.signal();
        match tokio::time::timeout(SHUTDOWN_WAIT, supervisor).await {
            Ok(_) => tracing::debug!("reload worker stopped"),
            Err(_) => {
                tracing::warn!(
                    "reload worker did not stop within {SHUTDOWN_WAIT:?}; abandoning it and \
                     continuing shutdown"
                );
            }
        }
    }
}

/// A running reload worker.
pub struct Reloader {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

impl Reloader {
    /// Start watching `path` and republishing into `router`.
    ///
    /// The connection is opened inside the worker and owned by it, so it is
    /// closed when the worker ends rather than at process teardown.
    pub fn start<P: Publish + Send + Sync + 'static>(
        path: PathBuf,
        router: Arc<P>,
        watcher: Watcher,
    ) -> Self {
        let (stop, mut stopped) = watch::channel(false);

        let handle = tokio::task::spawn_blocking(move || {
            // Blocking rather than async: every operation in the loop is a
            // synchronous SQLite call, and `spawn_blocking` keeps them off the
            // runtime's worker threads. A one-second sleep on an async thread
            // would be worse than the blocking pool it avoids.
            let mut watcher = watcher;
            let mut conn = match open(&path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "reload worker could not open the database");
                    return;
                }
            };

            loop {
                // Two ways to be told to stop, and the second one is the reason
                // this is not just a boolean check.
                //
                // A dropped `watch::Sender` does **not** flip the value: the
                // receiver keeps returning the last one it was sent, which is
                // `false`. So a `Reloader` dropped without `stop_and_join` —
                // by an early `?` during startup, before the daemon reaches its
                // shutdown path — would leave this loop running forever. It is
                // a `spawn_blocking` task, so the runtime then waits for it at
                // shutdown and the process hangs.
                //
                // `has_changed` returns `Err` once the sender is gone, which is
                // the signal a drop actually produces.
                if *stopped.borrow_and_update() || stopped.has_changed().is_err() {
                    return;
                }

                match watcher.tick(&conn, router.as_ref()) {
                    Tick::Published { domains, rules } => {
                        // R-3: logged only when the routing input actually
                        // changed and was published. A version change with an
                        // unchanged fingerprint is `Unrelated` and says nothing,
                        // which is what keeps the queue's commits out of this
                        // log from Milestone 3 onward.
                        tracing::info!(domains, rules, "routing reloaded");
                    }
                    Tick::Invalid { message, logged } => {
                        if logged {
                            tracing::warn!(
                                error = %message,
                                "the routing configuration in the database cannot be served; \
                                 the previous table is still in use"
                            );
                        }
                    }
                    Tick::Transient { message } => {
                        tracing::debug!(error = %message, "reload deferred");
                        // A connection-level failure is the one case where the
                        // version counter itself becomes meaningless, because
                        // `data_version` is comparable only across calls on one
                        // connection. Reopening therefore resets the baseline
                        // rather than adopting the new connection's value.
                        if conn_is_broken(&conn) {
                            match open(&path) {
                                Ok(fresh) => {
                                    conn = fresh;
                                    watcher.reconnected();
                                    tracing::info!("reload worker reconnected");
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "reload worker cannot reconnect");
                                }
                            }
                        }
                    }
                    Tick::Idle | Tick::Unrelated | Tick::Backoff => {}
                }

                std::thread::sleep(watcher.interval());
            }
        });

        Self { stop, handle }
    }

    /// A handle that can stop the worker, taken before [`Reloader::supervise`]
    /// consumes the join handle.
    ///
    /// Two handles because the two jobs are genuinely separate: supervision
    /// must be running *while* the daemon serves, so it can report a worker
    /// that dies mid-run, and stopping happens only at shutdown. A single
    /// object could not be both awaited and later signalled.
    pub fn stopper(&self) -> Stopper {
        Stopper {
            stop: self.stop.clone(),
        }
    }

    /// Watch for the worker ending on its own.
    ///
    /// A panicking task cannot report its own death — the panic unwinds past
    /// any logging it would have done — and a `JoinHandle` nobody awaits holds
    /// the result silently until someone asks. A daemon that spawned this and
    /// forgot it would keep serving the last published table forever, with
    /// routing frozen and nothing anywhere saying why.
    ///
    /// So the boundary is supervised from outside: the returned handle resolves
    /// when the worker ends for any reason, having said so.
    ///
    /// This is also the *only* join. Awaiting the returned handle transitively
    /// awaits the worker, so shutdown does not need a second path that owns the
    /// join handle directly — and two ways to stop one worker is two orderings
    /// to keep straight.
    pub fn supervise(self) -> JoinHandle<()> {
        supervise_handle(self.handle)
    }
}

/// The supervision itself, over any handle.
///
/// Split from [`Reloader::supervise`] so a test can hand it a task that panics.
/// The worker's own body has no failure injection point, and a branch that
/// cannot be reached from a test is a branch that is not known to work — this
/// module previously claimed a panic-supervision test it did not have.
fn supervise_handle(handle: JoinHandle<()>) -> JoinHandle<()> {
    tokio::spawn(async move {
        match handle.await {
            // A clean exit is either shutdown, which is expected, or the
            // worker giving up, which is not. It cannot tell the two apart
            // from here, so it says what is true of both: routing stops
            // changing.
            Ok(()) => tracing::debug!("the reload worker exited; routing will not change"),
            Err(e) if e.is_panic() => tracing::error!(
                error = %e,
                "the reload worker panicked; routing is frozen at the last published \
                 table until the daemon restarts"
            ),
            Err(e) => tracing::error!(error = %e, "the reload worker ended abnormally"),
        }
    })
}

fn open(path: &std::path::Path) -> Result<rusqlite::Connection, pigeon_db::DbError> {
    // Read-only: the worker never writes, and a connection that *cannot* write
    // is the cheapest way to keep it that way.
    //
    // It also sidesteps the trap in `M1-RELOAD.md` §2 — `data_version` does not
    // move for commits made on the same connection, so a detector that shared a
    // writer would be blind to exactly the writes it most needs to see.
    pigeon_db::open_read_only(path)
}

/// Whether a connection has failed in a way reopening might fix.
///
/// Probes with a real read against a table the loader uses. `SELECT 1` is
/// answered by the expression evaluator without touching a single page, so it
/// reports healthy for a connection whose storage has failed underneath it —
/// which is the only situation this function is ever asked about.
///
/// Measured, because the obvious example is the wrong one: for a *deleted*
/// file both probes still succeed, since the descriptor and the cached pages
/// outlive the directory entry. The case that separates them is corruption —
/// a file replaced underneath an open connection answers `SELECT 1` with `1`
/// and a table read with `database disk image is malformed`.
fn conn_is_broken(conn: &rusqlite::Connection) -> bool {
    conn.query_row("SELECT count(*) FROM domain", [], |r| r.get::<_, i64>(0))
        .is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// Every `tracing` event this test binary emits, in order.
    ///
    /// The supervisor's whole job is to *say* something — a test that only
    /// awaits its handle passes just as well when the reporting is deleted, so
    /// the log line is the assertion, not a side effect of one.
    ///
    /// Global rather than per-test because a subscriber is only visible to the
    /// thread that installed it, and the events under test are emitted from a
    /// spawned task on another thread. Tests therefore search the buffer for
    /// their own message rather than reading it positionally.
    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<(tracing::Level, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), message.0));
        }
    }

    impl Events {
        fn find(&self, level: tracing::Level, needle: &str) -> Option<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|(l, m)| *l == level && m.contains(needle))
                .map(|(_, m)| m.clone())
        }
    }

    fn events() -> Events {
        static EVENTS: OnceLock<Events> = OnceLock::new();
        EVENTS
            .get_or_init(|| {
                let events = Events::default();
                let _ = tracing_subscriber::registry()
                    .with(events.clone())
                    .try_init();
                events
            })
            .clone()
    }

    /// Wait for an event to arrive, or give up.
    ///
    /// The supervisor logs from a task the test does not hold, so the event can
    /// trail the await by a scheduling tick.
    async fn await_event(level: tracing::Level, needle: &str) -> String {
        let events = events();
        for _ in 0..200 {
            if let Some(message) = events.find(level, needle) {
                return message;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no {level} event containing {needle:?} was ever logged");
    }

    /// A migrated database that removes itself.
    struct Db(PathBuf);

    impl Db {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "pigeond-reload-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("pigeon.db");
            let mut conn = pigeon_db::open(&path).unwrap();
            pigeon_db::migrate(&mut conn, &path).unwrap();
            Self(dir)
        }
        fn path(&self) -> PathBuf {
            self.0.join("pigeon.db")
        }
    }

    impl Drop for Db {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn router() -> Arc<pigeon_route::Router> {
        Arc::new(pigeon_route::Router::new(pigeon_route::Snapshot::default()))
    }

    #[tokio::test]
    async fn shutdown_signals_and_joins() {
        let db = Db::new("shutdown");
        let r = Reloader::start(db.path(), router(), Watcher::new());
        let stopper = r.stopper();
        let supervisor = r.supervise();

        // Bounded well under `SHUTDOWN_WAIT`, so a worker that ignored the
        // signal would fail this rather than pass slowly.
        tokio::time::timeout(
            std::time::Duration::from_secs(4),
            stopper.stop_and_join(supervisor),
        )
        .await
        .expect("shutdown did not join the worker");
    }

    #[tokio::test]
    async fn a_dropped_reloader_does_not_leave_the_worker_running() {
        // The lifecycle case this module had no test for, and the reason the
        // bug survived review.
        //
        // Startup starts the worker, then something between there and the
        // listener fails and returns early. The `Reloader` is dropped without
        // `stop_and_join`, so the worker is never signalled — and a dropped
        // `watch::Sender` does not flip the value the receiver reads. Without
        // the closed-channel check, this loops forever, and because it is a
        // `spawn_blocking` task the runtime waits for it and the process hangs.
        //
        // Asserted by the test completing: the runtime cannot shut down while
        // a blocking task is running, so a leaked worker times out here.
        let db = Db::new("dropped");
        {
            let r = Reloader::start(db.path(), router(), Watcher::new());
            drop(r);
        }

        // Long enough for the worker to reach the top of its loop and notice.
        tokio::time::sleep(pigeon_route::reload::POLL * 2).await;
    }

    #[tokio::test]
    async fn a_worker_that_gives_up_is_reported() {
        // The worker giving up on its own: a path that is not a database, so it
        // logs and returns before its first tick. What is asserted is that the
        // supervisor then says routing has stopped changing — awaiting the
        // handle alone would pass with all of the reporting deleted.
        let events = events();
        let r = Reloader::start(
            PathBuf::from("/nonexistent/directory/pigeon.db"),
            router(),
            Watcher::new(),
        );
        let supervisor = r.supervise();

        tokio::time::timeout(std::time::Duration::from_secs(4), supervisor)
            .await
            .expect("the supervisor did not observe the worker ending")
            .expect("the supervisor task itself failed");

        // The worker's own complaint, and then the supervisor's.
        assert!(
            events
                .find(tracing::Level::ERROR, "could not open the database")
                .is_some(),
            "the worker did not report why it gave up"
        );
        await_event(tracing::Level::DEBUG, "routing will not change").await;
    }

    #[tokio::test]
    async fn a_panicking_worker_is_reported_as_a_panic() {
        // The branch the daemon exists to have: a worker that dies mid-run
        // cannot log its own death, because the panic unwinds past any logging
        // it would have done, and a `JoinHandle` nobody awaits holds the result
        // silently. Routing then freezes with nothing anywhere saying why.
        //
        // Injected through `supervise_handle` rather than through the worker,
        // which has no failure point to reach: the worker is a `spawn_blocking`
        // task, so this is one too, and `JoinError::is_panic` is what the branch
        // actually keys on.
        events();
        let handle = tokio::task::spawn_blocking(|| panic!("simulated reload worker panic"));

        tokio::time::timeout(std::time::Duration::from_secs(4), supervise_handle(handle))
            .await
            .expect("the supervisor did not observe the panic")
            .expect("the supervisor task itself failed");

        // Not merely "an error was logged": a panic must be distinguishable
        // from a clean exit, because the operator responses differ — one is a
        // restart, the other is shutdown working correctly.
        let message = await_event(tracing::Level::ERROR, "panicked").await;
        assert!(
            message.contains("frozen"),
            "the panic report did not say routing had frozen: {message}"
        );
    }

    #[test]
    fn the_liveness_probe_reads_the_database() {
        // Regression for a probe that reported healthy for every failure it was
        // meant to catch. `SELECT 1` never touches a page, so it answers from
        // the expression evaluator alone.
        //
        // The failure injected is corruption rather than deletion, because a
        // deleted file is not actually a failure the connection can see: the
        // descriptor and the cached pages outlive the directory entry, and both
        // probes keep succeeding. Replacing the file underneath an open
        // connection is what makes a real page read fail.
        let db = Db::new("probe");
        let conn = pigeon_db::open_read_only(&db.path()).unwrap();
        // Read once first, so the connection is genuinely established and the
        // corruption is discovered on a later read rather than at open.
        assert!(
            !conn_is_broken(&conn),
            "a healthy connection read as broken"
        );

        std::fs::write(db.path(), vec![0x41; 40 * 1024]).unwrap();

        assert_eq!(
            conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).ok(),
            Some(1),
            "the naive probe would have to fail here for the old one to have worked"
        );
        assert!(
            conn_is_broken(&conn),
            "the probe did not notice that the database underneath it was gone"
        );
    }

    #[tokio::test]
    async fn the_worker_publishes_a_change() {
        // End to end through the worker rather than through `Watcher::tick`:
        // that the loop actually calls the detector, on the connection it
        // opened, and installs what comes back.
        let db = Db::new("publishes");
        let router = router();
        let r = Reloader::start(db.path(), Arc::clone(&router), Watcher::new());

        let writer = pigeon_db::open(&db.path()).unwrap();
        let me = pigeon_db::repo::Address::parse("me@example.net").unwrap();
        pigeon_db::repo::add_domain(&writer, "example.com", Some(&me)).unwrap();
        writer
            .execute("UPDATE domain SET status = 'active'", [])
            .unwrap();
        pigeon_db::repo::add_alias(
            &writer,
            "example.com",
            "hello",
            pigeon_db::repo::AliasKind::Forward,
            &[],
        )
        .unwrap();

        let mut published = false;
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let snap = router.for_transaction();
            let a = pigeon_types::Address::parse("hello@example.com").unwrap();
            if matches!(snap.resolve(&a), pigeon_route::Decision::Forward { .. }) {
                published = true;
                break;
            }
        }

        let stopper = r.stopper();
        let supervisor = r.supervise();
        stopper.stop_and_join(supervisor).await;

        assert!(published, "the worker never published a committed change");
    }
}
