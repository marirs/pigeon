//! Claiming due deliveries, and finishing them without overwriting somebody
//! else's work.
//!
//! # Ownership fencing
//!
//! A claim is a lease, and a lease can expire while the worker holding it is
//! still running — stopped by the scheduler, blocked on a socket, paused by a
//! debugger. When it does, a replacement claims the row and starts its own
//! attempt. The original worker then finishes and tries to record a result for
//! an attempt that is no longer the one in progress.
//!
//! Nothing about `claimed_by` prevents that. A worker identity is reusable by
//! construction — the same host, the same name after a restart — so an update
//! conditional on "the row is mine" cannot distinguish *this* attempt from a
//! previous one that happened to have the same owner.
//!
//! So every claim carries a **token unique to that claim**, and every update
//! that records an outcome is conditional on it. A worker whose lease expired
//! finds its update matched zero rows, and reports that rather than clobbering
//! the result its replacement produced.
//!
//! # Attempts count claims, not remote attempts
//!
//! `attempts` is incremented when a row is claimed, so a worker that dies
//! mid-attempt does not leave a delivery that looks untried and retrying at
//! full rate. That makes it crash accounting, and it deliberately does **not**
//! decide anything terminal: a run of local crashes says nothing about the
//! destination, and letting it produce a permanent verdict would manufacture a
//! delivery failure out of a Pigeon failure. Expiry is governed by age.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::SpoolId;

/// How long a claim is good for, in seconds.
///
/// **It must exceed the delivery deadline.** A lease that expires while the
/// attempt it covers is still running gets the row reclaimed underneath a live
/// worker: the replacement connects to the same destination, and the first
/// worker's result is fenced and discarded — so a message that was delivered
/// once is delivered twice, and the outcome the remote actually gave is thrown
/// away.
///
/// The alternative is renewing the lease beneath the deadline, which is more
/// machinery for the same guarantee. A bounded delivery already has an upper
/// bound; a lease longer than it is enough, and the only cost of the margin is
/// how long a genuinely dead worker's row waits before somebody else takes it.
///
/// [`assert_lease_exceeds_deadline`] is what keeps the two from drifting apart.
pub const DEFAULT_LEASE_SECONDS: i64 = 2400;

/// Refuse a lease that does not outlast the deadline it covers.
///
/// Called at startup rather than checked in a comment: the two constants live
/// in different crates, and the failure they produce — duplicate deliveries
/// under load — looks like a remote problem rather than a configuration one.
pub fn assert_lease_exceeds_deadline(lease_seconds: i64, deadline_seconds: i64) {
    assert!(
        lease_seconds > deadline_seconds,
        "a claim lease of {lease_seconds}s does not outlast the {deadline_seconds}s delivery \
         deadline: a row would be reclaimed underneath a running attempt, and the outcome the \
         remote gave would be discarded as fenced"
    );
}

/// A token unique to one claim.
///
/// Random, not a counter: a counter resets when the process does, and two runs
/// handing out `1` would let a claim from before a restart fence-check as
/// current. Randomness is what makes "this attempt" mean this attempt across
/// restarts, hosts and clock steps.
pub fn random_token() -> String {
    let mut bytes = [0u8; 16];
    // A failure here means the OS RNG is unavailable, which is not a condition
    // to paper over with a weaker token: the fence is what stops two workers
    // recording results for one delivery.
    getrandom::fill(&mut bytes).expect("the system RNG is unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A claimed delivery, and the token that proves the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub delivery_id: i64,
    pub message_id: i64,
    pub spool_id: SpoolId,
    pub destination: String,
    /// The SRS return path to transmit, exactly as it was stored at
    /// acceptance.
    pub return_path: String,
    /// When the message was accepted, which is what the give-up horizon is
    /// measured from.
    pub received_at: i64,
    pub attempts: i64,
    /// Unique to this claim. Every update that records an outcome carries it.
    pub token: String,
}

/// What happened when a claim was completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The row was updated.
    Recorded,
    /// The claim no longer owned the row: its lease expired and something else
    /// has it. The result is **discarded**, deliberately — the replacement's
    /// attempt is the one in progress, and overwriting it would replace a live
    /// outcome with a stale one.
    Fenced,
}

/// How an attempt ended.
#[derive(Debug, Clone)]
pub enum Outcome {
    Delivered {
        code: u16,
        response: String,
    },
    /// Temporary: retry after `next_attempt_at`.
    Deferred {
        code: Option<u16>,
        response: String,
        next_attempt_at: i64,
    },
    /// Permanent, and about the *destination* — a 5xx, not a local fault.
    Failed {
        code: u16,
        response: String,
    },
}

/// Claim up to `batch` deliveries that are due.
///
/// `IMMEDIATE`, because two workers selecting the same rows and then updating
/// them would both succeed under deferred locking, and both would send.
pub fn claim(
    conn: &mut Connection,
    worker: &str,
    lease_seconds: i64,
    batch: usize,
    now: i64,
    token: impl Fn() -> String,
) -> rusqlite::Result<Vec<Claim>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let due: Vec<(i64, i64, String, String, String, i64, i64)> = {
        let mut stmt = tx.prepare(
            "SELECT d.id, d.message_id, m.spool_id, d.destination, m.return_path,
                    m.received_at, d.attempts
               FROM delivery d
               JOIN message m ON m.id = d.message_id
              WHERE d.state IN ('queued','deferred')
                -- Frozen rows are held back deliberately, and holding them back
                -- has to happen here rather than at the attempt: a claim taken
                -- and then discarded would count as an attempt and move the
                -- backoff on, so an operator's freeze would quietly push the
                -- retry schedule out.
                AND d.frozen_at IS NULL
                AND d.next_attempt_at <= ?1
              ORDER BY d.next_attempt_at
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![now, batch as i64], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };

    let mut claims = Vec::with_capacity(due.len());
    for (delivery_id, message_id, spool_id, destination, return_path, received_at, attempts) in due
    {
        let token = token();
        tx.execute(
            "UPDATE delivery
                SET state = 'delivering', claimed_by = ?1, claim_token = ?2,
                    lease_expires_at = ?3, next_attempt_at = NULL,
                    attempts = attempts + 1
              WHERE id = ?4",
            rusqlite::params![worker, token, now + lease_seconds, delivery_id],
        )?;

        // A spool identifier that will not parse means the row was written by
        // something other than acceptance. Skipped rather than claimed, so the
        // worker does not try to read a path it should never construct.
        let Ok(spool_id) = SpoolId::new(&spool_id) else {
            continue;
        };

        claims.push(Claim {
            delivery_id,
            message_id,
            spool_id,
            destination,
            return_path,
            received_at,
            attempts: attempts + 1,
            token,
        });
    }

    tx.commit()?;
    Ok(claims)
}

/// Reclaim deliveries whose lease has expired.
///
/// The worker holding one may still be alive — which is exactly why the claim
/// token exists. Reclaiming makes the row available; fencing makes the old
/// worker's result harmless.
pub fn expire_leases(conn: &mut Connection, now: i64, backoff: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE delivery
            SET state = 'deferred', claimed_by = NULL, claim_token = NULL,
                lease_expires_at = NULL, next_attempt_at = ?1
          WHERE state = 'delivering' AND lease_expires_at <= ?2",
        rusqlite::params![now + backoff, now],
    )
}

/// Record how an attempt ended, if this claim still owns the row.
pub fn complete(
    conn: &Connection,
    claim: &Claim,
    outcome: &Outcome,
    now: i64,
) -> rusqlite::Result<Applied> {
    // Every one of these is conditional on the token *and* on the row still
    // being in `delivering`: a replacement that has already finished has moved
    // it on, and the token alone would not catch a row reclaimed and then
    // claimed again by the same worker.
    let changed = match outcome {
        Outcome::Delivered { code, response } => conn.execute(
            "UPDATE delivery
                SET state='delivered', terminal_at=?1, claimed_by=NULL, claim_token=NULL,
                    lease_expires_at=NULL, next_attempt_at=NULL, last_code=?2, last_response=?3
              WHERE id=?4 AND claim_token=?5 AND state='delivering'",
            rusqlite::params![now, code, response, claim.delivery_id, claim.token],
        )?,
        Outcome::Deferred {
            code,
            response,
            next_attempt_at,
        } => conn.execute(
            "UPDATE delivery
                SET state='deferred', claimed_by=NULL, claim_token=NULL, lease_expires_at=NULL,
                    next_attempt_at=?1, last_code=?2, last_response=?3
              WHERE id=?4 AND claim_token=?5 AND state='delivering'",
            rusqlite::params![
                next_attempt_at,
                code,
                response,
                claim.delivery_id,
                claim.token
            ],
        )?,
        Outcome::Failed { code, response } => conn.execute(
            "UPDATE delivery
                SET state='failed', terminal_at=?1, claimed_by=NULL, claim_token=NULL,
                    lease_expires_at=NULL, next_attempt_at=NULL, last_code=?2, last_response=?3,
                    notification = CASE WHEN ?6 = '' THEN 'none' ELSE 'owed' END
              WHERE id=?4 AND claim_token=?5 AND state='delivering'",
            rusqlite::params![
                now,
                code,
                response,
                claim.delivery_id,
                claim.token,
                claim.return_path
            ],
        )?,
    };

    if changed == 0 {
        return Ok(Applied::Fenced);
    }

    let (kind, code, response) = match outcome {
        Outcome::Delivered { code, response } => ("deliver", Some(*code), response),
        Outcome::Deferred { code, response, .. } => ("defer", *code, response),
        Outcome::Failed { code, response } => ("fail", Some(*code), response),
    };
    conn.execute(
        "INSERT INTO delivery_event(delivery_id, at, kind, code, response)
         VALUES(?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![claim.delivery_id, now, kind, code, response],
    )?;

    Ok(Applied::Recorded)
}

/// Give up on a delivery that has been trying for too long.
///
/// Governed by **age**, not by attempt count: a run of local crashes says
/// nothing about the destination, and letting `attempts` decide would
/// manufacture a permanent delivery failure out of a Pigeon failure.
pub fn expire_old(conn: &Connection, horizon_seconds: i64, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE delivery
            SET state='expired', terminal_at=?1, next_attempt_at=NULL,
                claimed_by=NULL, claim_token=NULL, lease_expires_at=NULL,
                notification = CASE
                    WHEN (SELECT return_path FROM message WHERE id = delivery.message_id) = ''
                    THEN 'none' ELSE 'owed' END
          WHERE state IN ('queued','deferred')
            -- Strictly older, so a message gets the whole window rather than
            -- being given up on at the instant it elapses.
            AND (SELECT received_at FROM message WHERE id = delivery.message_id) < ?2",
        rusqlite::params![now, now - horizon_seconds],
    )
}

/// Hold a message's deliveries back, or let them go again.
///
/// Freezing stops Pigeon *trying*; it does not stop the clock. The horizon
/// still runs, so a destination frozen and forgotten expires and reports like
/// any other — which is the outcome that does not silently swallow mail.
///
/// Terminal rows are left alone: there is nothing to hold back, and freezing
/// one would suggest a retry that is never coming.
pub fn freeze(conn: &Connection, selector: &Selector, now: i64) -> rusqlite::Result<usize> {
    let (clause, param) = selector.sql();
    conn.execute(
        &format!(
            "UPDATE delivery SET frozen_at = ?2
              WHERE frozen_at IS NULL
                AND state IN ('queued','deferred')
                AND {clause}"
        ),
        rusqlite::params![param, now],
    )
}

/// Release held deliveries.
///
/// The next attempt time is left as it was: a thawed row is due when it was
/// already due, and resetting it would send every held message at once to a
/// destination that may still be the reason they were held.
pub fn thaw(conn: &Connection, selector: &Selector) -> rusqlite::Result<usize> {
    let (clause, param) = selector.sql();
    conn.execute(
        &format!("UPDATE delivery SET frozen_at = NULL WHERE frozen_at IS NOT NULL AND {clause}"),
        rusqlite::params![param],
    )
}

/// Make held or deferred deliveries due immediately.
///
/// Thaws as well, because "retry this now" from an operator who froze it means
/// what it says. Terminal rows are not revived: a delivered message is not
/// resent, and a failed one has already had its report generated — reviving it
/// would produce a second delivery of a message whose sender was told it failed.
pub fn retry_now(conn: &Connection, selector: &Selector, now: i64) -> rusqlite::Result<usize> {
    let (clause, param) = selector.sql();
    conn.execute(
        &format!(
            "UPDATE delivery
                SET next_attempt_at = ?2, frozen_at = NULL
              WHERE state IN ('queued','deferred') AND {clause}"
        ),
        rusqlite::params![param, now],
    )
}

/// Which deliveries an operator's command is about.
#[derive(Debug, Clone)]
pub enum Selector {
    /// One message, by its spool identifier — the id the `250` gave the sender.
    Message(String),
    /// Every delivery to a destination domain.
    Domain(String),
    /// Everything held or due.
    All,
}

impl Selector {
    /// The `WHERE` fragment and the value it binds as `?1`.
    ///
    /// A fragment rather than a built string: the value is always bound, so a
    /// domain named `'; DROP TABLE` is a domain nothing matches rather than a
    /// statement. Callers bind their own values from `?2` onwards.
    fn sql(&self) -> (&'static str, String) {
        match self {
            Self::Message(spool_id) => (
                "message_id = (SELECT id FROM message WHERE spool_id = ?1)",
                spool_id.clone(),
            ),
            // Matched on the destination's domain, which is what an operator
            // means by "freeze example.net": the mail going *there*.
            Self::Domain(domain) => (
                "lower(substr(destination, instr(destination, '@') + 1)) = lower(?1)",
                domain.clone(),
            ),
            Self::All => ("?1 = ?1", String::new()),
        }
    }
}

/// One row of `pigeon queue list`.
#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub delivery_id: i64,
    pub spool_id: String,
    pub destination: String,
    pub state: String,
    pub attempts: i64,
    pub next_attempt_at: Option<i64>,
    pub frozen_at: Option<i64>,
    pub last_code: Option<i64>,
    pub last_response: Option<String>,
    pub original_sender: String,
    pub received_at: i64,
}

/// What is in the queue, newest arrivals last.
///
/// Terminal rows are excluded unless asked for: after a day they are most of
/// the table, and an operator asking "what is stuck?" does not mean "what has
/// ever been sent from this host?".
pub fn list(
    conn: &Connection,
    include_terminal: bool,
    limit: usize,
) -> rusqlite::Result<Vec<QueueEntry>> {
    let mut stmt = conn.prepare(
        "SELECT d.id, m.spool_id, d.destination, d.state, d.attempts,
                d.next_attempt_at, d.frozen_at, d.last_code, d.last_response,
                m.original_sender, m.received_at
           FROM delivery d
           JOIN message m ON m.id = d.message_id
          WHERE (?1 OR d.state NOT IN ('delivered','failed','expired'))
          ORDER BY m.received_at, d.id
          LIMIT ?2",
    )?;

    let rows = stmt.query_map(rusqlite::params![include_terminal, limit as i64], |r| {
        Ok(QueueEntry {
            delivery_id: r.get(0)?,
            spool_id: r.get(1)?,
            destination: r.get(2)?,
            state: r.get(3)?,
            attempts: r.get(4)?,
            next_attempt_at: r.get(5)?,
            frozen_at: r.get(6)?,
            last_code: r.get(7)?,
            last_response: r.get(8)?,
            original_sender: r.get(9)?,
            received_at: r.get(10)?,
        })
    })?;
    rows.collect()
}

/// One thing that happened to a delivery.
#[derive(Debug, Clone)]
pub struct Event {
    pub at: i64,
    pub kind: String,
    /// The remote's code, when a remote said anything. A local failure has
    /// none, which is the difference between "they refused it" and "we could
    /// not send it".
    pub code: Option<i64>,
    pub response: Option<String>,
}

/// Everything recorded about one delivery, in order.
pub fn events(conn: &Connection, delivery_id: i64) -> rusqlite::Result<Vec<Event>> {
    let mut stmt = conn.prepare(
        "SELECT at, kind, code, response FROM delivery_event
          WHERE delivery_id = ?1 ORDER BY at, id",
    )?;
    let rows = stmt.query_map([delivery_id], |r| {
        Ok(Event {
            at: r.get(0)?,
            kind: r.get(1)?,
            code: r.get(2)?,
            response: r.get(3)?,
        })
    })?;
    rows.collect()
}

/// Delete the records of messages that were settled long enough ago.
///
/// The body goes when every delivery is terminal and nothing is owed a report
/// (`M3-DESIGN.md` §8). The **rows** outlive it, because "what happened to this
/// message?" is a question an operator asks days later, and answering it from
/// the log alone is guesswork. This is what eventually collects them.
///
/// Age is measured from `body_deleted_at`, which is set exactly when the
/// message became releasable — so the window is "how long after Pigeon was
/// finished with a message can its outcome still be explained", which is the
/// question the window is actually about. A message that is not finished with
/// has no `body_deleted_at` and is never collected here, however old.
///
/// Two things are kept beyond the window regardless:
///
/// - **A message some delivery still points at as its `notified_by`.** That row
///   is the DSN which explains a failure, and deleting it would leave the
///   failure it reported with a dangling `enqueued` — the notification outcome
///   unexplainable, which is precisely what retention is for. It becomes
///   collectable once the failure's own record has gone.
/// - **Anything not actually settled**: a delivery still in flight, or a report
///   still owed. `body_deleted_at` should not be set in either case, and this
///   does not rely on that being true.
pub fn expire_metadata(
    conn: &Connection,
    retain_seconds: i64,
    now: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        // The `IS NOT NULL` is redundant with the comparison below — SQL
        // compares NULL to nothing — and is kept because the intent is what a
        // reader checks: only a message Pigeon has finished with has a window
        // at all. No mutation can fail on removing it while the comparison
        // stands, which is the reason it is written down here rather than
        // assumed.
        "DELETE FROM message
          WHERE body_deleted_at IS NOT NULL
            -- Strictly older, so a message gets the whole window.
            AND body_deleted_at < ?1
            AND NOT EXISTS (
                SELECT 1 FROM delivery d
                 WHERE d.message_id = message.id
                   AND (d.state NOT IN ('delivered','failed','expired')
                        OR d.notification = 'owed')
            )
            AND NOT EXISTS (
                SELECT 1 FROM delivery r WHERE r.notified_by = message.id
            )",
        [now - retain_seconds],
    )
}

/// Whether a delivery still exists and in what state, for tests and for
/// operator tooling.
pub fn state_of(conn: &Connection, delivery_id: i64) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT state FROM delivery WHERE id = ?1",
        [delivery_id],
        |r| r.get(0),
    )
    .optional()
}
