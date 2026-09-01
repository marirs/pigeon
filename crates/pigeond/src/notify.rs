//! Turning owed failures into reports the sender can read.
//!
//! Runs beside the delivery loop rather than inside it: a report is itself a
//! message to be delivered, so generating one is queue *input*, and mixing it
//! into the loop that drains the queue would make the two compete for the same
//! permits.

use pigeon_auth::{Day, SrsError};
use pigeon_spool::dsn::{self, Enqueued, Owed, ReversalFailure};
use pigeon_spool::{Spool, SpoolId};

use crate::Queue;

/// Reverse a stored return path back into the address that sent the message.
///
/// The classification is the point. A report can only be abandoned for a
/// **permanent** condition — an address that is not a return path at all, or
/// one whose tag will never verify. A ring that cannot be read *right now* is a
/// local fault, and treating it as permanent would consume an obligation
/// because a file was briefly unreadable.
pub fn reverse(
    srs: &pigeon_auth::Srs,
    return_path: &str,
    now: Day,
) -> Result<String, (ReversalFailure, String)> {
    let local = return_path
        .rsplit_once('@')
        .map(|(l, _)| l)
        .unwrap_or(return_path);

    match srs.reverse(local, now) {
        Ok(reversed) => Ok(reversed.address),

        // Nothing about waiting produces a recipient from these.
        Err(e @ SrsError::NotRewritten) => Err((ReversalFailure::Permanent, e.to_string())),
        Err(e @ SrsError::Malformed(_)) => Err((ReversalFailure::Permanent, e.to_string())),
        Err(e @ SrsError::BadTag) => Err((ReversalFailure::Permanent, e.to_string())),
        // Expired is permanent because time only moves further away from the
        // window: the address was valid and will not be again.
        Err(e @ SrsError::Expired { .. }) => Err((ReversalFailure::Permanent, e.to_string())),

        // These are all about *this host* rather than about the address.
        //
        // A future-dated address means the clock jumped backwards here; the
        // ring cases mean the file is unreadable or has no eligible key. Every
        // one of them can be fixed, and the address may be perfectly good — so
        // the obligation stays owed and the next pass tries again.
        Err(e) => Err((ReversalFailure::Local, e.to_string())),
    }
}

/// Generate reports for everything currently owed.
///
/// Returns how many were queued. Errors are logged rather than returned: this
/// runs on a timer, and a failure to report one message must not stop the
/// others.
pub async fn run_once(
    queue: &Queue,
    spool: &Spool,
    srs: &pigeon_auth::Srs,
    hostname: &str,
    now: i64,
) -> usize {
    let owed = {
        let conn = queue.conn.lock().await;
        match dsn::owed(&conn) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = %e, "cannot read owed notifications");
                return 0;
            }
        }
    };

    let mut queued = 0;
    for report in owed {
        if generate(queue, spool, srs, hostname, &report, now).await {
            queued += 1;
        }
    }
    queued
}

/// One report: reverse, render, install, enqueue.
async fn generate(
    queue: &Queue,
    spool: &Spool,
    srs: &pigeon_auth::Srs,
    hostname: &str,
    report: &Owed,
    now: i64,
) -> bool {
    let recipient = match reverse(srs, &report.return_path, Day::now()) {
        Ok(address) => address,

        Err((ReversalFailure::Local, why)) => {
            // Kept owed. The next pass tries again, and an operator who fixes
            // the ring gets the backlog delivered rather than discovering that
            // it was thrown away while the file was unreadable.
            tracing::warn!(
                message = report.message_id,
                error = %why,
                "cannot reverse a return path yet; the report stays owed"
            );
            return false;
        }

        Err((ReversalFailure::Permanent, why)) => {
            // There is no address to send to and there never will be. The
            // obligation is discharged as `abandoned` — durably distinct from
            // "no report was required" — and an operator hears about it,
            // because a sender is being left without an answer.
            tracing::error!(
                message = report.message_id,
                return_path = %report.return_path,
                error = %why,
                "a failure report can never be sent: the return path will not reverse"
            );
            // An operator alert belongs here as well as the log: a sender
            // being left without an answer is not something to discover by
            // reading logs. `pigeon-alert` has no transport until Milestone 5,
            // so this is the error log for now — recorded as a gap rather than
            // left to look finished.
            //
            // The delivery event below is the durable half, and it is written
            // whether or not anybody is watching the log.

            let conn = queue.conn.lock().await;
            if let Err(e) = dsn::abandon_report(&conn, report, &why, now) {
                tracing::error!(error = %e, "cannot record an abandoned report");
            }
            return false;
        }
    };

    // The original headers, if the body is still there. A report quotes them,
    // and retention keeps the body until nothing is owed — so a missing one is
    // a local fault, described in the report rather than hidden.
    let original = spool.read(&report.spool_id).await.ok();
    let headers = original
        .as_deref()
        .and_then(pigeon_spool::report::headers_of);
    if headers.is_none() {
        tracing::error!(
            message = report.message_id,
            spool_id = %report.spool_id,
            "reporting a failure without the original headers: the stored message is unreadable"
        );
    }

    let dsn_spool_id = match SpoolId::new(&format!("dsn-{}-{}", report.message_id, now)) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "cannot name a report");
            return false;
        }
    };

    let body = pigeon_spool::report::render(
        report,
        hostname,
        &recipient,
        headers.as_deref(),
        &pigeon_types::rfc5322_date(now),
        &boundary(now, report.message_id),
    );

    // Registered before it is written, so the sweep leaves it alone until the
    // transaction below has decided its fate.
    let pending = spool.begin(&dsn_spool_id);
    if let Err(e) = spool.install(&dsn_spool_id, &[&body]).await {
        tracing::error!(error = %e, "cannot spool a report");
        return false;
    }

    let enqueued = {
        let mut conn = queue.conn.lock().await;
        dsn::enqueue(
            &mut conn,
            report,
            &dsn_spool_id,
            body.len() as i64,
            &recipient,
            now,
        )
    };

    match enqueued {
        Ok(Enqueued::Queued { .. }) => {
            drop(pending);
            tracing::info!(
                message = report.message_id,
                to = %recipient,
                failures = report.entries.len(),
                "queued a delivery failure report"
            );
            true
        }
        Ok(Enqueued::Superseded) => {
            // Another generator reported these. Nothing was committed, so the
            // file this rendered is nobody's.
            if let Err(e) = dsn::discard_uncommitted(spool, &dsn_spool_id).await {
                tracing::warn!(error = %e, "cannot remove a superseded report");
            }
            drop(pending);
            tracing::debug!(
                message = report.message_id,
                "another worker reported this failure"
            );
            false
        }
        Err(e) => {
            // The transaction failed, so nothing refers to the file. Removing
            // it is safe for the same reason the superseded path is.
            if let Err(e) = dsn::discard_uncommitted(spool, &dsn_spool_id).await {
                tracing::warn!(error = %e, "cannot remove an unqueued report");
            }
            drop(pending);
            tracing::error!(error = %e, "cannot queue a report");
            false
        }
    }
}

/// A MIME boundary that cannot appear in the parts it separates.
fn boundary(now: i64, message_id: i64) -> String {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return format!("=_pigeon_{now}_{message_id}");
    }
    format!(
        "=_pigeon_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Release bodies whose deliveries are all terminal and whose reports are all
/// queued.
///
/// The row is marked first and the file removed second. A crash between them
/// leaves an orphan, which the sweep collects; the other order would leave a
/// row claiming a body that is gone, which every reader treats as an integrity
/// failure — permanently, and correctly.
pub async fn release_bodies(queue: &Queue, spool: &Spool, now: i64) -> usize {
    let candidates: Vec<(i64, SpoolId)> = {
        let conn = queue.conn.lock().await;
        let mut stmt = match conn
            .prepare("SELECT id, spool_id FROM message WHERE body_deleted_at IS NULL LIMIT 200")
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot look for releasable bodies");
                return 0;
            }
        };
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)));
        match rows {
            Ok(rows) => rows
                .filter_map(|r| r.ok())
                .filter_map(|(id, spool_id)| SpoolId::new(&spool_id).ok().map(|s| (id, s)))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "cannot read releasable bodies");
                return 0;
            }
        }
    };

    let mut released = 0;
    for (message_id, spool_id) in candidates {
        let mark = {
            let conn = queue.conn.lock().await;
            match dsn::body_may_be_removed(&conn, message_id) {
                Ok(true) => dsn::mark_body_released(&conn, message_id, now),
                Ok(false) => continue,
                Err(e) => {
                    tracing::error!(error = %e, "cannot check whether a body is releasable");
                    continue;
                }
            }
        };

        match mark {
            Ok(true) => {
                if let Err(e) = spool.remove(&spool_id).await {
                    // The row already says the body is gone, which is the
                    // recoverable direction: the file is now an orphan and the
                    // sweep will collect it.
                    tracing::warn!(error = %e, "a released body could not be removed yet");
                }
                released += 1;
            }
            // Somebody else released it; the file is theirs to remove.
            Ok(false) => {}
            Err(e) => tracing::error!(error = %e, "cannot mark a body released"),
        }
    }
    released
}

/// Spool identifiers the database still refers to, for the sweep.
///
/// `None` when the answer is unknown, and the caller must then not sweep at
/// all. An empty set is a *claim* — that nothing is referenced — and returning
/// one because a query failed would authorise deleting every spooled message
/// on the host. The two are not interchangeable, which is exactly the kind of
/// thing a comment saying "the safe failure" can paper over: an earlier version
/// of this function said that and returned the empty set anyway.
pub async fn referenced(queue: &Queue) -> Option<std::collections::HashSet<String>> {
    let conn = queue.conn.lock().await;
    let mut stmt = match conn.prepare("SELECT spool_id FROM message WHERE body_deleted_at IS NULL")
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot list referenced spool files; not sweeping");
            return None;
        }
    };
    match stmt.query_map([], |r| r.get::<_, String>(0)) {
        Ok(rows) => {
            let mut set = std::collections::HashSet::new();
            for row in rows {
                match row {
                    Ok(id) => {
                        set.insert(id);
                    }
                    // A row that will not read means the listing is incomplete,
                    // and an incomplete listing is indistinguishable from a
                    // shorter one. Refusing to sweep is the only answer that
                    // cannot delete a queued message.
                    Err(e) => {
                        tracing::error!(error = %e, "incomplete spool listing; not sweeping");
                        return None;
                    }
                }
            }
            Some(set)
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot read referenced spool files; not sweeping");
            None
        }
    }
}
