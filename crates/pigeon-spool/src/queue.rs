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
