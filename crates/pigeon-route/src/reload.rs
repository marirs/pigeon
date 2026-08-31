//! Watching SQLite for routing changes and republishing.
//!
//! Design: `docs/M1-RELOAD.md`. The `Arc` swap in [`crate::Router`] was already
//! built and tested; what is here is the change detector, and its only real
//! property is that **it cannot miss a commit**.
//!
//! A reload that is late is a stale routing table for a second. A reload that is
//! missed is a stale routing table until someone restarts the daemon, with
//! nothing anywhere saying so.

use std::time::Duration;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::LoadError;
use crate::router::Publish;
use crate::snapshot::{DomainInput, Snapshot};

/// How often the version is checked.
///
/// A constant rather than configuration: the check is one pragma on an already
/// open connection, so there is no wrong value to tune, and a slower poll only
/// delays a reload nobody is waiting on synchronously.
pub const POLL: Duration = Duration::from_secs(1);

/// Longest the rebuild backoff grows to, **counted in polls**.
///
/// Expressed in polls rather than in wall-clock time because [`POLL`] is a
/// constant, which makes the two equivalent — and because a count is
/// deterministic. A duration would need a clock injected into [`Watcher::tick`]
/// purely so a test could assert the throttling, and a safety property tested
/// against a clock is a safety property tested by timing.
///
/// It bounds wasted work for a configuration that will never build. It does
/// **not** bound how quickly a fix is noticed: polling continues throughout, and
/// a version not seen before cancels the backoff.
const BACKOFF_MAX_POLLS: u32 = 60;

/// What one iteration did, for logging and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// The version had not moved.
    Idle,
    /// The version moved, and the routing input was identical.
    ///
    /// The commit touched something else — the queue, delivery metadata, a
    /// setting. Consumed silently, because `data_version` is a doorbell and not
    /// a diff.
    Unrelated,
    /// A new routing table was published.
    Published { domains: usize, rules: usize },
    /// The configuration does not build. The last good table is still serving.
    Invalid { message: String, logged: bool },
    /// The database could not be read. The last good table is still serving.
    Transient { message: String },
    /// The rebuild was skipped because this version already failed and its
    /// backoff has not expired. Polling continued.
    Backoff,
}

/// A version whose rebuild failed, and how long to leave it alone.
#[derive(Debug, Clone, Copy)]
struct Failed {
    version: i64,
    /// Polls still to skip before the next rebuild attempt.
    skip_remaining: u32,
    /// How many to skip after the next failure. Doubles, capped.
    next_skip: u32,
}

/// The detector's state between iterations.
///
/// Separate from the loop so a test can drive one step at a time and assert
/// what it did — the ordering rules here are not observable from the outside
/// otherwise.
pub struct Watcher {
    /// The last version whose routing input was fully handled.
    ///
    /// `None` forces an unconditional rebuild, and it starts that way. Startup
    /// builds its snapshot on its own connection before this worker exists, so
    /// adopting the version seen here as a baseline would put any commit made
    /// in between *inside* the baseline and never rebuild it.
    seen: Option<i64>,
    /// Fingerprint of the routing input behind the currently published table.
    published: Option<[u8; 32]>,
    /// The version that failed, and the state of its rebuild throttle.
    failed: Option<Failed>,
    /// The version whose failure has already been logged, so a configuration
    /// that will never build does not log every second.
    logged_failure: Option<i64>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Watcher {
    pub fn new() -> Self {
        Self {
            seen: None,
            published: None,
            failed: None,
            logged_failure: None,
        }
    }

    /// Called after a reconnect.
    ///
    /// `data_version` is comparable only across calls on the **same**
    /// connection: it counts changes that connection has observed, not commits
    /// to the database. An old connection reading 3 and a fresh one reading 2
    /// coexist happily, and a brand-new connection still reads 2 after three
    /// further commits.
    ///
    /// So adopting the new connection's value would set `seen` to a number with
    /// no relationship to what was published, and skip every change until the
    /// new counter caught up. Reconnecting returns to the unconditional state.
    pub fn reconnected(&mut self) {
        self.seen = None;
        self.failed = None;
    }

    /// One iteration.
    ///
    /// The ordering here is the design. Every line is placed against a way of
    /// missing a commit.
    pub fn tick(&mut self, conn: &Connection, router: &impl Publish) -> Tick {
        self.tick_with(conn, router, || {})
    }

    /// Whether a baseline has been established.
    ///
    /// `false` means the next tick rebuilds whatever the version says. Exposed
    /// because the two states are otherwise indistinguishable from outside —
    /// and a test that asserts "a reconnect rebuilds" by committing a change
    /// first passes for the wrong reason whenever the fresh connection's
    /// counter happens to differ, which is most of the time.
    pub fn has_baseline(&self) -> bool {
        self.seen.is_some()
    }

    /// The recorded baseline, or `None`.
    ///
    /// Exposed so a test can assert that a failure did not advance it. The
    /// alternative — inferring it from behaviour — needs a later commit to
    /// observe, and that commit changes the version and hides the bug.
    pub fn baseline(&self) -> Option<i64> {
        self.seen
    }

    /// [`Watcher::tick`], with a hook run **after the rows are read** and before
    /// the version is recorded.
    ///
    /// That is the window the ordering rule is about. A commit landing here is
    /// not in the snapshot just built, and a version read *after* it would
    /// include it — so recording that version consumes a commit that was never
    /// built, and the next tick finds nothing to do.
    ///
    /// The window before the rows are read is the harmless one: a commit there
    /// may or may not be in the snapshot, and either way the recorded version
    /// predates it, so the next tick rebuilds.
    ///
    /// Producing this by timing would make a safety property depend on a race,
    /// so the window is opened deliberately. In production the hook is `||{}`
    /// and the compiler removes it.
    pub fn tick_with(
        &mut self,
        conn: &Connection,
        router: &impl Publish,
        between: impl FnOnce(),
    ) -> Tick {
        // Read BEFORE the transaction. Recording a version read *after* the
        // rows would let a commit land in between and never be seen again: the
        // next poll would compare against the newer number and find nothing to
        // do.
        //
        // Reading it early can only cost a redundant rebuild, which is the
        // direction that is safe to be wrong in.
        let version = match data_version(conn) {
            Ok(v) => v,
            Err(e) => {
                return Tick::Transient {
                    message: format!("cannot read data_version: {e}"),
                };
            }
        };

        // A version not seen before is never throttled: the throttle below is
        // guarded on `f.version == version`, so a record left over from an
        // older failure simply does not match and the rebuild proceeds. The fix
        // for an invalid configuration arrives as a new commit, and it is the
        // one commit that most deserves prompt pickup.
        //
        // An earlier version cleared `failed` here explicitly. That line looked
        // load-bearing and was not — the guard already does the work, and no
        // mutation of it could be made to fail a test, which is what exposed it.

        // The throttle is checked *before* the `seen` comparison, because a
        // failed version is deliberately never recorded in `seen` — recording
        // it would mean a transient failure permanently swallowed a real
        // change. So `failed` is the only state that knows this version has
        // already been tried.
        //
        // Note what has already happened by this point: the version was read.
        // Throttling the rebuild must never throttle detection.
        if let Some(mut f) = self.failed
            && f.version == version
            && f.skip_remaining > 0
        {
            f.skip_remaining -= 1;
            self.failed = Some(f);
            return Tick::Backoff;
        }
        // Falling through past that means either no failure is recorded for this
        // version, or its throttle has expired and it is time to try again.

        if self.seen == Some(version) {
            return Tick::Idle;
        }

        let (inputs, fingerprint) = match load_and_fingerprint(conn) {
            Ok(pair) => pair,
            // A row this build cannot interpret is not a transient fault: it
            // will read the same way on every retry, and treating it as one
            // means retrying every second and logging at debug rather than
            // saying once, loudly, that the configuration cannot be served.
            Err(e @ LoadError::UnknownStatus { .. }) => {
                return self.record_invalid(version, format!("{e}"));
            }
            Err(e) => {
                // Not consumed. A transient failure that advanced `seen` would
                // permanently swallow a real change.
                return Tick::Transient {
                    message: format!("{e}"),
                };
            }
        };

        // The window the ordering rule is about: the rows are read, and the
        // version recorded below is the one read *before* them.
        between();

        // `data_version` moves on *every* commit, including ones that touch no
        // routing at all — and from Milestone 3 the queue shares this database
        // and commits continuously. The fingerprint is what separates "the
        // database changed" from "routing changed".
        if self.published == Some(fingerprint) {
            self.seen = Some(version);
            return Tick::Unrelated;
        }

        match Snapshot::build(inputs) {
            Ok(built) => {
                let domains = built.snapshot.domain_names().count();
                let rules = built.snapshot.rule_count();

                // Publication itself can fail — the daemon derives signing keys
                // from the snapshot as it installs it — and a failure here is
                // the same kind of event as a configuration that will not
                // build: the previous state keeps serving, and the operator is
                // told once rather than every second.
                if let Err(e) = router.publish(built.snapshot) {
                    return self.record_invalid(version, e);
                }
                self.published = Some(fingerprint);
                self.seen = Some(version);
                self.failed = None;
                self.logged_failure = None;
                Tick::Published { domains, rules }
            }
            Err(e) => {
                // The last known good table stays published: a running server
                // with a stale-but-valid routing table beats one with none.
                self.record_invalid(version, format!("{e}"))
            }
        }
    }

    /// Record a version whose configuration cannot be served.
    ///
    /// `seen` is not advanced, so the version is still pending. What is
    /// throttled is only the rebuild — see [`Watcher::tick`].
    fn record_invalid(&mut self, version: i64, message: String) -> Tick {
        let next_skip = match self.failed {
            Some(f) if f.version == version => (f.next_skip * 2).min(BACKOFF_MAX_POLLS),
            _ => 1,
        };
        self.failed = Some(Failed {
            version,
            skip_remaining: next_skip,
            next_skip,
        });

        let logged = self.logged_failure != Some(version);
        if logged {
            self.logged_failure = Some(version);
        }
        Tick::Invalid { message, logged }
    }

    /// How long to wait before the next iteration.
    ///
    /// Always [`POLL`]. The backoff lives in [`Watcher::tick`] and gates the
    /// rebuild, not the poll — suspending the poll would mean a fix committed
    /// during a sixty-second backoff waits sixty seconds to be noticed.
    pub fn interval(&self) -> Duration {
        POLL
    }
}

fn data_version(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("PRAGMA data_version", [], |r| r.get(0))
}

/// Read the routing input and fingerprint it, in one read transaction.
///
/// The transaction is not decoration. [`crate::load`] runs a query for domains,
/// then one per domain for its aliases, then one per alias for its
/// destinations — so without it, a commit landing partway through produces a
/// configuration assembled from two different states of the database. That
/// hybrid never existed and nobody committed it, and it would be published as
/// though somebody had.
///
/// An earlier version of this function said "in one read transaction" in its
/// documentation and opened none. The comment was the specification and the
/// code did not meet it.
///
/// `unchecked_transaction` because the caller holds `&Connection`: the worker's
/// connection is read-only and single-threaded, so the borrow rules a `&mut`
/// would enforce are already guaranteed by construction.
fn load_and_fingerprint(conn: &Connection) -> Result<(Vec<DomainInput>, [u8; 32]), LoadError> {
    let tx = conn.unchecked_transaction().map_err(LoadError::Sqlite)?;
    let inputs = crate::load(&tx)?;
    let fingerprint = fingerprint(&inputs);
    // Read-only, so there is nothing to commit; dropping rolls back. Explicit
    // because "this transaction is never committed" should not have to be
    // inferred from the absence of a call.
    drop(tx);
    Ok((inputs, fingerprint))
}

/// A canonical hash of everything the routing table is built from.
///
/// Canonical because the comparison has to answer "is this the same routing" and
/// not "did these rows arrive in the same order". `load` already returns domains
/// and aliases in a stated order; destinations are sorted here so a fan-out
/// listed differently does not read as a change.
fn fingerprint(inputs: &[DomainInput]) -> [u8; 32] {
    let mut h = Sha256::new();
    for d in inputs {
        h.update(d.name.as_bytes());
        h.update([
            u8::from(d.gate.inbound_enabled),
            u8::from(d.gate.outbound_enabled),
            u8::from(d.plus_addressing),
        ]);
        h.update(d.gate.status.as_str().as_bytes());
        match &d.default_destination {
            Some(dest) => h.update(format!("default={dest}").as_bytes()),
            None => h.update(b"default=none"),
        }
        match &d.catchall {
            Some(c) => match &c.destination {
                Some(dests) => {
                    let mut d: Vec<String> = dests.iter().map(ToString::to_string).collect();
                    d.sort();
                    h.update(format!("catchall={}", d.join(",")).as_bytes());
                }
                None => h.update(b"catchall=inherit"),
            },
            None => h.update(b"catchall=none"),
        }
        for a in &d.aliases {
            let mut dests: Vec<String> = a.destinations.iter().map(ToString::to_string).collect();
            dests.sort();
            h.update(
                format!(
                    "alias={} reject={} to={}\x01",
                    a.pattern,
                    a.reject,
                    dests.join(",")
                )
                .as_bytes(),
            );
        }
        h.update(b"\x02");
    }
    h.finalize().into()
}

/// Why the first snapshot could not be built.
#[derive(Debug, thiserror::Error)]
pub enum InitialError {
    #[error("{0}")]
    Load(#[from] LoadError),
    #[error("{0}")]
    Build(#[from] crate::BuildError),
}

/// Build the first snapshot and the watcher state that matches it.
///
/// Used by startup, so the published table and the fingerprint the worker
/// compares against agree from the very first tick — otherwise the worker's
/// first rebuild would see a fingerprint it has never recorded and publish an
/// identical table, logging a reload that did not happen.
///
/// The *version* is deliberately not captured. See [`Watcher::seen`].
pub fn initial(conn: &Connection) -> Result<(Snapshot, Vec<crate::Report>, Watcher), InitialError> {
    let (inputs, fingerprint) = load_and_fingerprint(conn)?;
    let built = Snapshot::build(inputs)?;

    let mut watcher = Watcher::new();
    watcher.published = Some(fingerprint);
    // `seen` stays `None`, so the worker's first tick rebuilds unconditionally.
    // That is what closes the window between this build and the worker starting.
    Ok((built.snapshot, built.reports, watcher))
}
