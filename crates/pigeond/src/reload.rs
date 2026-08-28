//! Running the change detector, and supervising it.
//!
//! The detector itself is `pigeon_route::reload`. What is here is the loop
//! around it, the shutdown path, and — the part that is easy to get wrong — the
//! supervision that reports a worker which stopped.

use std::path::PathBuf;
use std::sync::Arc;

use pigeon_route::{Router, Tick, Watcher};
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
    pub fn start(path: PathBuf, router: Arc<Router>, watcher: Watcher) -> Self {
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
                if *stopped.borrow_and_update() {
                    return;
                }

                match watcher.tick(&conn, &router) {
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
        tokio::spawn(async move {
            match self.handle.await {
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
fn conn_is_broken(conn: &rusqlite::Connection) -> bool {
    conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
        .is_err()
}
