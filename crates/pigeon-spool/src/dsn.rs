//! Telling the sender, exactly once.
//!
//! A delivery that fails permanently or ages out owes its sender a report
//! (`M3-DESIGN.md` §9). Producing one has three hazards, and only the first is
//! obvious:
//!
//! 1. **A crash between the failure and the report** would leave a delivery
//!    that looks handled and a sender who never hears anything. Solved by
//!    keeping "the remote refused" and "the sender was told" in separate
//!    columns: the failure stays `owed` until the report is committed.
//!
//! 2. **Two generators running at once** would each read the same owed set,
//!    each render a report, and each enqueue it — one failure, two bounces to
//!    the same person. Solved by making the transaction *conditionally claim*
//!    the exact rows it rendered: the update matches only rows still `owed`,
//!    and if the count differs the whole DSN is rolled back and its spool file
//!    removed. Rendering before the transaction is safe; committing without
//!    checking is not.
//!
//! 3. **A report that cannot be delivered** — a return path that will not
//!    reverse, or a null sender — must not become an endless retry. A null
//!    sender owes nothing at all; an unreversible one is a local fault, said
//!    out loud, and not a message queued to nowhere.

use rusqlite::{Connection, TransactionBehavior};

use crate::{Spool, SpoolError, SpoolId};

/// One message's worth of owed reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owed {
    pub message_id: i64,
    /// The SRS return path the message was accepted with. Empty means the
    /// message was itself a bounce.
    pub return_path: String,
    pub original_sender: String,
    pub spool_id: SpoolId,
    pub entries: Vec<Entry>,
}

/// One failed destination, and the addresses the sender wrote to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub delivery_id: i64,
    pub destination: String,
    /// From `recipient_delivery`. A report naming only the destination tells a
    /// sender delivery failed to a mailbox they have never heard of.
    pub original_recipients: Vec<String>,
    /// `failed` or `expired`, which need different wording and different
    /// action from whoever reads them.
    pub state: String,
    pub code: Option<i64>,
    pub response: Option<String>,
}

/// Everything currently owed, grouped by message.
///
/// Grouped because a message with three failed destinations gets one report
/// (§9.3), and because the conditional claim in [`enqueue`] needs the exact set
/// it rendered.
pub fn owed(conn: &Connection) -> rusqlite::Result<Vec<Owed>> {
    let mut stmt = conn.prepare(
        "SELECT d.id, d.message_id, d.destination, d.state, d.last_code, d.last_response,
                m.return_path, m.original_sender, m.spool_id
           FROM delivery d
           JOIN message m ON m.id = d.message_id
          WHERE d.notification = 'owed'
          ORDER BY d.message_id, d.destination",
    )?;

    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, Option<i64>>(4)?,
            r.get::<_, Option<String>>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
        ))
    })?;

    let mut out: Vec<Owed> = Vec::new();
    for row in rows {
        let (id, message_id, destination, state, code, response, return_path, sender, spool) = row?;
        let recipients = recipients_for(conn, id)?;

        let entry = Entry {
            delivery_id: id,
            destination,
            original_recipients: recipients,
            state,
            code,
            response,
        };

        match out.last_mut() {
            Some(last) if last.message_id == message_id => last.entries.push(entry),
            _ => {
                let Ok(spool_id) = SpoolId::new(&spool) else {
                    // A row whose spool identifier will not parse was not
                    // written by acceptance. Skipped rather than reported on,
                    // since nothing here can find its body.
                    continue;
                };
                out.push(Owed {
                    message_id,
                    return_path,
                    original_sender: sender,
                    spool_id,
                    entries: vec![entry],
                });
            }
        }
    }
    Ok(out)
}

fn recipients_for(conn: &Connection, delivery_id: i64) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT o.address FROM original_recipient o
           JOIN recipient_delivery rd ON rd.original_recipient_id = o.id
          WHERE rd.delivery_id = ?1
          ORDER BY o.address",
    )?;
    stmt.query_map([delivery_id], |r| r.get(0))?.collect()
}

/// What happened to an attempt to enqueue a report.
#[derive(Debug, PartialEq, Eq)]
pub enum Enqueued {
    /// The report is queued and the failures are marked as notified.
    Queued { dsn_message_id: i64 },
    /// Another generator got there first: at least one of the rows this report
    /// covers is no longer `owed`. Nothing was committed, and the caller must
    /// remove the spool file it installed.
    ///
    /// Deliberately not an error. Two generators racing is ordinary; what would
    /// not be ordinary is both of them winning.
    Superseded,
}

/// Queue a rendered report, if and only if it still describes owed work.
///
/// The transaction does three things together, and the order inside matters
/// less than the fact that they are one commit:
///
/// - claim the rows, conditionally on each still being `owed`,
/// - insert the report's own message and delivery,
/// - mark the claimed rows as notified, pointing at it.
///
/// If the conditional claim does not match every row the report was rendered
/// for, the whole thing rolls back. The caller removes the spool file, and the
/// rows stay owed for whoever did win to report — or for the next pass.
#[allow(clippy::too_many_arguments)]
pub fn enqueue(
    conn: &mut Connection,
    report: &Owed,
    dsn_spool_id: &SpoolId,
    size_bytes: i64,
    // Where the report goes: the *reversed* return path, so it reaches the
    // original sender rather than arriving back at Pigeon.
    recipient: &str,
    now: i64,
) -> rusqlite::Result<Enqueued> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // The report's own rows go in first, because the conditional claim below
    // has to set `notification` and `notified_by` in one statement — the schema
    // holds them to be one fact, and a claim that set only the first would fail
    // its CHECK. Inserting first and rolling back is free; the rows exist only
    // inside this transaction until it commits.
    //
    // The report is an ordinary queued message. Its envelope sender is null,
    // which is what stops two systems bouncing at each other forever, and it
    // goes through the same spool and queue — a bounce lost on a restart is a
    // sender who never learns.
    tx.execute(
        "INSERT INTO message(spool_id, return_path, original_sender, size_bytes,
                             received_at, routing_revision, routing_fingerprint)
         VALUES(?1, '', '', ?2, ?3, 0, x'00')",
        rusqlite::params![dsn_spool_id.as_str(), size_bytes, now],
    )?;
    let dsn_message_id = tx.last_insert_rowid();

    tx.execute(
        "INSERT INTO original_recipient(message_id, address) VALUES(?1, ?2)",
        rusqlite::params![dsn_message_id, recipient],
    )?;
    let recipient_id = tx.last_insert_rowid();

    tx.execute(
        "INSERT INTO delivery(message_id, destination, next_attempt_at) VALUES(?1, ?2, ?3)",
        rusqlite::params![dsn_message_id, recipient, now],
    )?;
    let delivery_id = tx.last_insert_rowid();

    tx.execute(
        "INSERT INTO recipient_delivery(original_recipient_id, delivery_id) VALUES(?1, ?2)",
        rusqlite::params![recipient_id, delivery_id],
    )?;

    // The conditional claim. Each row must still be `owed`: if another
    // generator took any of them, this report describes work that is already
    // being reported and committing it would be a second bounce to the same
    // person.
    let mut claimed = 0usize;
    for entry in &report.entries {
        claimed += tx.execute(
            "UPDATE delivery SET notification = 'enqueued', notified_by = ?1
              WHERE id = ?2 AND notification = 'owed'",
            rusqlite::params![dsn_message_id, entry.delivery_id],
        )?;
    }

    if claimed != report.entries.len() {
        // Roll back rather than report on a subset — including the report's own
        // rows, which is why they were safe to insert first. The caller removes
        // the spool file.
        tx.rollback()?;
        return Ok(Enqueued::Superseded);
    }

    for entry in &report.entries {
        tx.execute(
            "INSERT INTO delivery_event(delivery_id, at, kind, response)
             VALUES(?1, ?2, 'notify', ?3)",
            rusqlite::params![entry.delivery_id, now, recipient],
        )?;
    }

    tx.commit()?;
    Ok(Enqueued::Queued { dsn_message_id })
}

/// Record that a report can never be sent, and stop owing it.
///
/// For the one case R-4's "never discard" does not cover: there is no address
/// to send to. A return path that will not reverse is a local fault — a rotated
/// key deleted too early, a corrupted row — and queueing a message to nowhere
/// would leave the body pinned forever behind a notification that cannot
/// happen.
///
/// Loud rather than quiet: the caller logs and alerts, and the event stays in
/// the delivery log for whoever asks why a sender heard nothing.
pub fn abandon_report(
    conn: &Connection,
    report: &Owed,
    reason: &str,
    now: i64,
) -> rusqlite::Result<()> {
    for entry in &report.entries {
        conn.execute(
            "UPDATE delivery SET notification = 'none'
              WHERE id = ?1 AND notification = 'owed'",
            [entry.delivery_id],
        )?;
        conn.execute(
            "INSERT INTO delivery_event(delivery_id, at, kind, response)
             VALUES(?1, ?2, 'notify', ?3)",
            rusqlite::params![entry.delivery_id, now, format!("not reported: {reason}")],
        )?;
    }
    Ok(())
}

/// Whether a message's body may be removed.
///
/// Every delivery terminal **and** nothing still owed: a report quotes the
/// original headers, so the body outlives the deliveries by as long as the
/// reports take. Removing it earlier makes the DSN's own rendering fall back to
/// "the headers could not be included", which is a worse report for no reason.
pub fn body_may_be_removed(conn: &Connection, message_id: i64) -> rusqlite::Result<bool> {
    let pending: i64 = conn.query_row(
        "SELECT count(*) FROM delivery
          WHERE message_id = ?1
            AND (state NOT IN ('delivered','failed','expired') OR notification = 'owed')",
        [message_id],
        |r| r.get(0),
    )?;
    Ok(pending == 0)
}

/// Remove a spool file for a report that was not committed.
///
/// Its own function because the caller must not confuse it with retention:
/// this one runs on a path where nothing referenced the file, and it is safe
/// precisely because the transaction rolled back.
pub async fn discard_uncommitted(spool: &Spool, id: &SpoolId) -> Result<(), SpoolError> {
    spool.remove(id).await
}
