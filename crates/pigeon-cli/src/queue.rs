//! `pigeon queue`: what is waiting, why, and what to do about it.
//!
//! Everything here reads or writes the queue directly rather than asking the
//! daemon. There is no control socket, and adding one to answer "what is stuck"
//! would be adding a protocol, a permission model and a failure mode to a
//! question SQLite already answers. The daemon notices the change on its next
//! poll, which is where the queue's own concurrency rules take over: a frozen
//! row is skipped at claim time, so an operator's freeze cannot race an attempt
//! into a half state.

use pigeon_spool::queue::{self, QueueEntry, Selector};

/// `pigeon queue list`.
pub fn list(
    conn: &rusqlite::Connection,
    include_terminal: bool,
    limit: usize,
    json: bool,
) -> anyhow::Result<u8> {
    let entries = queue::list(conn, include_terminal, limit)?;

    if json {
        crate::json::ok(serde_json::json!({
            "entries": entries.iter().map(render).collect::<Vec<_>>(),
        }));
        return Ok(crate::exit::OK);
    }

    if entries.is_empty() {
        println!(
            "{}",
            if include_terminal {
                "The queue is empty."
            } else {
                "Nothing is waiting."
            }
        );
        return Ok(crate::exit::OK);
    }

    println!(
        "{:<24} {:<28} {:<10} {:>4}  NEXT",
        "MESSAGE", "DESTINATION", "STATE", "TRY"
    );
    for e in &entries {
        println!(
            "{:<24} {:<28} {:<10} {:>4}  {}",
            e.spool_id,
            truncate(&e.destination, 28),
            state_of(e),
            e.attempts,
            when(e)
        );
    }

    // The last thing a destination said is the most useful line in the file
    // when something is stuck, and it is too long for the table.
    if let Some(stuck) = entries.iter().find(|e| e.last_response.is_some()) {
        println!(
            "\nMost recent response, for {}:\n  {}",
            stuck.spool_id,
            stuck.last_response.as_deref().unwrap_or("")
        );
    }
    Ok(crate::exit::OK)
}

/// `pigeon queue show <message>`: everything recorded about one message.
pub fn show(conn: &rusqlite::Connection, spool_id: &str, json: bool) -> anyhow::Result<u8> {
    let entries: Vec<QueueEntry> = queue::list(conn, true, 10_000)?
        .into_iter()
        .filter(|e| e.spool_id == spool_id)
        .collect();

    if entries.is_empty() {
        anyhow::bail!(
            "no message {spool_id} in the queue.\n\n  \
             Records are kept for 30 days after a message is finished with; \
             one older than that has been collected."
        );
    }

    if json {
        crate::json::ok(serde_json::json!({
            "message": spool_id,
            "deliveries": entries.iter().map(|e| {
                let events = queue::events(conn, e.delivery_id).unwrap_or_default();
                let mut value = render(e);
                value["events"] = serde_json::json!(events.iter().map(|e| {
                    serde_json::json!({
                        "at": e.at,
                        "kind": e.kind,
                        "code": e.code,
                        "response": e.response,
                    })
                }).collect::<Vec<_>>());
                value
            }).collect::<Vec<_>>(),
        }));
        return Ok(crate::exit::OK);
    }

    println!("{spool_id}\n");
    println!("  From       {}", entries[0].original_sender);
    println!("  Received   {}", stamp(entries[0].received_at));

    for e in &entries {
        println!("\n  {} — {}", e.destination, state_of(e));
        println!("    attempts   {}", e.attempts);
        if let Some(response) = &e.last_response {
            println!("    last said  {response}");
        }
        for event in queue::events(conn, e.delivery_id)? {
            println!(
                "    {}  {:<8} {}",
                stamp(event.at),
                event.kind,
                match (event.code, event.response) {
                    (Some(c), Some(r)) => format!("{c} {r}"),
                    (None, Some(r)) => r,
                    (Some(c), None) => c.to_string(),
                    (None, None) => String::new(),
                }
            );
        }
    }
    Ok(crate::exit::OK)
}

/// `pigeon queue retry`, `freeze` and `thaw`.
pub fn act(
    conn: &rusqlite::Connection,
    action: Action,
    selector: Selector,
    json: bool,
) -> anyhow::Result<u8> {
    let now = crate::now();
    let (verb, changed) = match action {
        Action::Retry => ("retried", queue::retry_now(conn, &selector, now)?),
        Action::Freeze => ("frozen", queue::freeze(conn, &selector, now)?),
        Action::Thaw => ("released", queue::thaw(conn, &selector)?),
    };

    if json {
        crate::json::ok(serde_json::json!({ "action": verb, "deliveries": changed }));
    } else if changed == 0 {
        // Said plainly rather than as an error: "nothing matched" is a fact
        // about the queue, and an operator who freezes an already-quiet domain
        // has not made a mistake.
        println!("Nothing to change.");
    } else {
        println!("{changed} deliveries {verb}.");
        if matches!(action, Action::Freeze) {
            println!(
                "\nFreezing stops Pigeon trying. It does not stop the clock: these still\n\
                 expire at the five-day horizon and their senders are still told."
            );
        }
    }
    Ok(crate::exit::OK)
}

#[derive(Clone, Copy)]
pub enum Action {
    Retry,
    Freeze,
    Thaw,
}

fn render(e: &QueueEntry) -> serde_json::Value {
    serde_json::json!({
        "message": e.spool_id,
        "destination": e.destination,
        "state": e.state,
        "frozen": e.frozen_at.is_some(),
        "attempts": e.attempts,
        "next_attempt_at": e.next_attempt_at,
        "last_code": e.last_code,
        "last_response": e.last_response,
        "original_sender": e.original_sender,
        "received_at": e.received_at,
    })
}

/// Frozen is shown instead of the state, not beside it: a held row is not going
/// anywhere, and that is the fact an operator is looking for.
fn state_of(e: &QueueEntry) -> String {
    if e.frozen_at.is_some() {
        "frozen".into()
    } else {
        e.state.clone()
    }
}

fn when(e: &QueueEntry) -> String {
    match (e.frozen_at, e.next_attempt_at) {
        (Some(_), _) => "held".into(),
        (None, Some(at)) => stamp(at),
        (None, None) => "—".into(),
    }
}

/// A timestamp an operator can compare with their own clock.
///
/// Whole seconds since the epoch, rendered as a date: the queue stores Unix
/// time, and a CLI that printed "3 minutes ago" would be inventing a clock
/// while the daemon and the database agree on one.
fn stamp(at: i64) -> String {
    // Written out rather than pulling in a date library for one format. The
    // arithmetic is the civil-from-days algorithm, which is exact for every
    // date this will ever be given.
    let days = at.div_euclid(86_400);
    let secs = at.rem_euclid(86_400);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timestamp_is_the_clock_the_database_keeps() {
        // A CLI that printed "3 minutes ago" would be inventing a clock while
        // the daemon and the database agree on one.
        assert_eq!(stamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(stamp(1_000_000_000), "2001-09-09 01:46:40Z");
        // A leap day, which is where hand-rolled date arithmetic goes wrong.
        assert_eq!(stamp(1_709_164_800), "2024-02-29 00:00:00Z");
        assert_eq!(stamp(1_788_264_852), "2026-09-01 12:14:12Z");
    }

    #[test]
    fn a_long_destination_is_shortened_on_a_character_boundary() {
        // Truncating bytes would panic on a multi-byte address, and addresses
        // with non-ASCII local parts exist.
        assert_eq!(truncate("short@example.net", 28), "short@example.net");
        let long = "ünicode-address-that-is-quite-long@example.net";
        let cut = truncate(long, 10);
        assert_eq!(cut.chars().count(), 10);
        assert!(cut.ends_with('…'));
    }
}
