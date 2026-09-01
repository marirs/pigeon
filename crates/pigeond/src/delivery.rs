//! The delivery loop: claim, send, record.
//!
//! # The permit comes before the claim
//!
//! A claim is a lease with a deadline, and the deadline starts when the row is
//! claimed rather than when the sending starts. Claiming into an internal work
//! queue and waiting for a permit afterwards would let a row spend its lease in
//! memory — so by the time the transmission began, the lease could already have
//! expired, the row could have been reclaimed by another worker, and the
//! guarantee that the lease outlasts the delivery deadline would prove nothing.
//!
//! So the order is: permit, then claim, then read, then send, then record.
//! Nothing is claimed that is not about to be attempted.
//!
//! # A database transaction is never held across the network
//!
//! Reading the spool and transmitting happen with no transaction open. SQLite
//! admits one writer, and holding it for the length of a delivery to a slow
//! destination would stop acceptance for everyone else — the queue would be
//! serialised behind the worst remote server currently being tried.

use std::sync::Arc;
use std::time::Duration;

use pigeon_dns::MxLookup;
use pigeon_spool::queue::{self, Applied, Claim, Outcome};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;

use crate::{Forwarding, Queue, forward};

/// How long the loop waits when there is nothing due.
const IDLE_POLL: Duration = Duration::from_secs(2);

/// Backoff schedule, by attempt. Exponential to a ceiling, then flat until the
/// age horizon gives up (`M3-DESIGN.md` §7).
const BACKOFF_SECONDS: [i64; 5] = [60, 300, 900, 3600, 10800];
const BACKOFF_CEILING: i64 = 21600;

/// A running delivery loop.
pub struct Deliverer {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
    /// One permit per concurrent attempt. Holding all of them means nothing is
    /// in flight, which is what [`Deliverer::drain`] waits for.
    permits: Arc<Semaphore>,
    concurrency: usize,
}

/// How a drain ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Drained {
    /// Nothing was in flight by the time the bound expired.
    Complete,
    /// Attempts were still running. Not a failure: every claim carries a
    /// unique token, so an attempt abandoned here cannot complete a row that
    /// has since been reclaimed, and the row returns to the queue when its
    /// lease expires.
    Abandoned { in_flight: usize },
}

/// Everything the loop needs, so its signature does not grow a parameter per
/// dependency.
pub struct DeliveryConfig<R: MxLookup> {
    pub queue: Queue,
    pub spool: pigeon_spool::Spool,
    /// For reversing a return path into the address a report goes to.
    pub srs: Arc<pigeon_auth::Srs>,
    pub hostname: String,
    pub forwarding: Forwarding<R>,
    /// Bounded concurrency. Also the number of permits, and therefore the
    /// number of rows that can be claimed at once.
    pub concurrency: usize,
    pub lease_seconds: i64,
    /// How old a message may get before Pigeon gives up on it.
    pub horizon_seconds: i64,
    /// Identifies this process's claims: hostname plus a random boot value,
    /// never a PID, which is reused.
    pub worker: String,
}

impl Deliverer {
    pub fn start<R: MxLookup + 'static>(config: DeliveryConfig<R>) -> Self {
        let (stop, mut stopped) = watch::channel(false);
        let concurrency = config.concurrency;
        let permits = Arc::new(Semaphore::new(concurrency));
        let for_drain = Arc::clone(&permits);

        let handle = tokio::spawn(async move {
            let DeliveryConfig {
                queue,
                spool,
                srs,
                hostname,
                forwarding,
                lease_seconds,
                horizon_seconds,
                worker,
                ..
            } = config;
            let forwarding = Arc::new(forwarding);

            loop {
                if *stopped.borrow_and_update() || stopped.has_changed().is_err() {
                    return;
                }

                // The permit *first*. Everything after this is a row that is
                // about to be attempted, not one waiting in memory to be.
                let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                    return;
                };

                let now = crate::unix_now();
                housekeeping(
                    &queue,
                    &spool,
                    &srs,
                    &hostname,
                    now,
                    horizon_seconds,
                    lease_seconds,
                )
                .await;

                let claimed = {
                    let mut conn = queue.conn.lock().await;
                    queue::claim(
                        &mut conn,
                        &worker,
                        lease_seconds,
                        1,
                        now,
                        queue::random_token,
                    )
                };

                let claim = match claimed {
                    Ok(mut claims) => claims.pop(),
                    Err(e) => {
                        tracing::error!(error = %e, "cannot claim work from the queue");
                        None
                    }
                };

                let Some(claim) = claim else {
                    // Nothing due. The permit is released by dropping it here
                    // rather than being held across the sleep, so a burst of
                    // work is not throttled by an idle loop.
                    drop(permit);
                    // Woken by the stop signal as well as by the timer, so the
                    // task exits when it is told to rather than up to a poll
                    // later. No test fails without it — the permit is already
                    // released above, so a drain still returns promptly — but a
                    // worker that outlives its own shutdown by two seconds is
                    // one whose supervisor reports its exit after the process
                    // has moved on.
                    tokio::select! {
                        () = tokio::time::sleep(IDLE_POLL) => {}
                        _ = stopped.changed() => return,
                    }
                    continue;
                };

                let queue = queue.clone();
                let spool = spool.clone();
                let forwarding = Arc::clone(&forwarding);
                tokio::spawn(async move {
                    attempt(&queue, &spool, &forwarding, &claim).await;
                    drop(permit);
                });
            }
        });

        Self {
            stop,
            handle,
            permits: for_drain,
            concurrency,
        }
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Stop claiming, then wait for attempts already in flight.
    ///
    /// The order matters: claiming stops *first*, or the drain waits on work
    /// the worker is still taking on. What it waits for afterwards is bounded,
    /// because one attempt may legitimately run for the whole forward budget —
    /// half an hour against a slow receiver — and a shutdown that waited for
    /// that is a shutdown nobody will use.
    ///
    /// Leaving an attempt running is safe by construction rather than by luck:
    /// the claim it holds is fenced by a token nothing else can produce, so its
    /// completion cannot land on a row that has since been reclaimed, and the
    /// row itself returns to the queue when the lease expires.
    pub async fn drain(&self, bound: Duration) -> Drained {
        self.stop();

        let all = self.permits.acquire_many(self.concurrency as u32);
        match tokio::time::timeout(bound, all).await {
            Ok(_) => Drained::Complete,
            Err(_) => Drained::Abandoned {
                in_flight: self.concurrency - self.permits.available_permits(),
            },
        }
    }

    /// Wait for the loop to finish, reporting how it ended.
    pub fn supervise(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            match self.handle.await {
                Ok(()) => tracing::debug!("the delivery worker exited; nothing will be sent"),
                Err(e) if e.is_panic() => tracing::error!(
                    error = %e,
                    "the delivery worker panicked; queued mail will not move until restart"
                ),
                Err(e) => tracing::error!(error = %e, "the delivery worker ended abnormally"),
            }
        })
    }
}

/// Everything the loop does besides delivering: reclaim, expire, report,
/// release and sweep.
///
/// In this order, and the order is not arbitrary. Expiring produces owed
/// reports; reporting is what releases bodies; releasing is what makes files
/// collectable. Running them in any other order just means each step waits a
/// tick for the one before it.
#[allow(clippy::too_many_arguments)]
async fn housekeeping(
    queue: &Queue,
    spool: &pigeon_spool::Spool,
    srs: &pigeon_auth::Srs,
    hostname: &str,
    now: i64,
    horizon: i64,
    lease: i64,
) {
    let mut conn = queue.conn.lock().await;

    // A lease that expired means a worker died mid-attempt, or was stopped long
    // enough to be indistinguishable from one. The row becomes claimable again;
    // the claim token is what makes the old worker's late result harmless.
    match queue::expire_leases(&mut conn, now, lease) {
        Ok(0) => {}
        Ok(n) => tracing::warn!(count = n, "reclaimed deliveries whose lease had expired"),
        Err(e) => tracing::error!(error = %e, "cannot reclaim expired leases"),
    }

    match queue::expire_old(&conn, horizon, now) {
        Ok(0) => {}
        Ok(n) => tracing::warn!(count = n, "gave up on deliveries past the horizon"),
        Err(e) => tracing::error!(error = %e, "cannot expire old deliveries"),
    }
    drop(conn);

    // Reports for whatever is owed, including anything the expiry above just
    // produced.
    crate::notify::run_once(queue, spool, srs, hostname, now).await;

    // Bodies whose deliveries are all terminal and whose reports are all
    // queued. Marked released before the file is removed, so a crash leaves an
    // orphan rather than a row claiming a body that is gone.
    crate::notify::release_bodies(queue, spool, now).await;

    // And whatever an acceptance left behind by crashing before its commit.
    // Files being installed right now are registered with the spool and are
    // skipped; after a crash that register is empty, which is exactly when its
    // files are collectable.
    // Only with a listing that is known to be complete: an empty set claims
    // nothing is referenced, and sweeping on that claim deletes every queued
    // message.
    if let Some(referenced) = crate::notify::referenced(queue).await {
        match spool.sweep(&referenced).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "swept spool files no message refers to"),
            Err(e) => tracing::warn!(error = %e, "cannot sweep the spool"),
        }
    }
}

/// One attempt: read, transmit, record.
async fn attempt<R: MxLookup>(
    queue: &Queue,
    spool: &pigeon_spool::Spool,
    forwarding: &Forwarding<R>,
    claim: &Claim,
) {
    let outcome = match spool.read(&claim.spool_id).await {
        Ok(bytes) => transmit(forwarding, claim, &bytes).await,

        // A body that cannot be read is a *local* integrity failure, and it is
        // reported as one. Recording it as a remote rejection would tell the
        // sender their recipient refused the message, which is false and
        // unactionable — the fault is here, and an operator can fix it by
        // restoring the file or by learning that the disk is failing.
        //
        // Deferred rather than failed for the same reason: the message may
        // still be deliverable once the file is back, and if it never is, the
        // age horizon gives up on it and says so honestly.
        Err(e) => {
            tracing::error!(
                delivery = claim.delivery_id,
                spool_id = %claim.spool_id,
                error = %e,
                "cannot read a spooled message: local integrity failure, not a remote rejection"
            );
            Outcome::Deferred {
                code: None,
                response: format!("local integrity failure: {e}"),
                next_attempt_at: crate::unix_now() + backoff(claim.attempts),
            }
        }
    };

    let now = crate::unix_now();
    let conn = queue.conn.lock().await;
    match queue::complete(&conn, claim, &outcome, now) {
        Ok(Applied::Recorded) => {}
        Ok(Applied::Fenced) => {
            // The lease expired and something else owns the row. Its attempt is
            // the one in progress, so this result is discarded — deliberately,
            // and loudly enough to be visible if it becomes common, because
            // frequent fencing means the lease is too short for the deadline.
            tracing::warn!(
                delivery = claim.delivery_id,
                "an attempt finished after its lease expired; the result was discarded"
            );
        }
        Err(e) => tracing::error!(
            delivery = claim.delivery_id,
            error = %e,
            "cannot record a delivery outcome"
        ),
    }
}

async fn transmit<R: MxLookup>(
    forwarding: &Forwarding<R>,
    claim: &Claim,
    message: &[u8],
) -> Outcome {
    // The return path stored at acceptance, never recomputed, and the
    // destination this claim is for.
    match forward(
        forwarding,
        claim.attempts as u64,
        &claim.destination,
        &claim.return_path,
        message,
    )
    .await
    {
        Ok(remote) => Outcome::Delivered {
            code: 250,
            response: remote,
        },

        // Permanent means the *remote* refused it, or the domain said in DNS
        // that it accepts no mail. Only these become a failure the sender is
        // told about.
        Err(e) if e.is_permanent() => Outcome::Failed {
            code: 550,
            response: e.to_string(),
        },

        // Everything else — 4xx, connection failures, timeouts, DNS that could
        // not answer, a local TLS problem — is worth trying again. Bouncing on
        // any of them would lose mail that would have delivered.
        Err(e) => Outcome::Deferred {
            code: None,
            response: e.to_string(),
            next_attempt_at: crate::unix_now() + backoff(claim.attempts),
        },
    }
}

/// How long to wait before the next attempt.
///
/// Exponential to a ceiling, with jitter: a destination coming back after an
/// outage would otherwise receive every deferred message at the same instant
/// from every sender that backs off on the same curve.
pub fn backoff(attempts: i64) -> i64 {
    let base = BACKOFF_SECONDS
        .get((attempts.max(1) - 1) as usize)
        .copied()
        .unwrap_or(BACKOFF_CEILING);

    // Up to a quarter of the interval, added rather than subtracted so a retry
    // never lands earlier than the schedule says.
    let mut bytes = [0u8; 4];
    if getrandom::fill(&mut bytes).is_err() {
        return base;
    }
    let jitter = (u32::from_le_bytes(bytes) as i64) % (base / 4).max(1);
    base + jitter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_then_levels_off() {
        // A destination that is down for a day should not be retried every
        // minute for that whole day, and one that is down for a minute should
        // not wait six hours.
        let first = backoff(1);
        let later = backoff(4);
        assert!(first < later, "backoff does not grow: {first} then {later}");

        // Past the schedule it holds at the ceiling rather than growing without
        // bound: a message is given up on by age, so an interval longer than
        // the horizon would mean never trying again before then.
        let far = backoff(50);
        assert!(
            (BACKOFF_CEILING..BACKOFF_CEILING * 2).contains(&far),
            "backoff past the schedule is {far}"
        );
    }

    #[test]
    fn backoff_is_jittered() {
        // A destination coming back after an outage receives every deferred
        // message at once from every sender that backs off on the same curve.
        // The spread is what stops Pigeon being one of them.
        let samples: std::collections::HashSet<i64> = (0..50).map(|_| backoff(4)).collect();
        assert!(
            samples.len() > 1,
            "every backoff was identical: {:?}",
            samples
        );
    }

    #[test]
    fn backoff_never_lands_before_the_schedule_says() {
        // Jitter is added, not subtracted: a retry earlier than the interval
        // would make the schedule an upper bound rather than a floor, and a
        // destination asking for a delay would get less of one.
        for attempts in 1..=6 {
            let base = BACKOFF_SECONDS
                .get((attempts - 1) as usize)
                .copied()
                .unwrap_or(BACKOFF_CEILING);
            for _ in 0..20 {
                assert!(
                    backoff(attempts) >= base,
                    "attempt {attempts} backed off less than {base}"
                );
            }
        }
    }

    #[test]
    fn the_first_attempt_uses_the_first_interval() {
        // `attempts` is 1 on the first claim, not 0, and an off-by-one here
        // would either skip the first interval or index past the schedule.
        assert!(backoff(1) >= BACKOFF_SECONDS[0]);
        assert!(backoff(1) < BACKOFF_SECONDS[1]);
        // And zero, which the queue never produces, is treated as the first
        // attempt rather than panicking on a negative index.
        assert!(backoff(0) >= BACKOFF_SECONDS[0]);
    }
}
