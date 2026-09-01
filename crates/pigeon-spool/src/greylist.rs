//! Greylisting: refuse a new sender once, accept them when they come back.
//!
//! The bet is narrow and old: a real MTA retries a `4xx`, and most of what
//! sends spam does not. It is not a filter — it says nothing about the content
//! — and it is worth exactly as much as that bet, which is why it is off unless
//! configured.
//!
//! # What is remembered, and why it is a triplet
//!
//! `(client address, envelope sender, recipient)`.
//!
//! **Not the address alone**: a large provider's outbound pool has hundreds of
//! addresses, and the one that retries is rarely the one that tried first, so
//! an address-keyed greylist delays that sender for ever.
//!
//! **Not the message**: a message id or a body hash would let a sender skip the
//! delay by changing one byte, which is a thing spam engines do by default.
//!
//! # The delay is per triplet, not per message
//!
//! Once a triplet is admitted it stays admitted. Delaying every message from a
//! known sender would be a permanent tax for a one-off benefit, and the benefit
//! is only ever collected the first time.
//!
//! # It refuses during the conversation
//!
//! `4xx` at `RCPT`, so the message stays with the system that has a copy of it.
//! Nothing here can cause a message to be accepted and then discarded.

use rusqlite::{Connection, OptionalExtension};

/// What to do with a recipient, as far as greylisting is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Seen before and past its delay, or never subject to one.
    Pass,
    /// Refuse this attempt with a `4xx`, and say when it will be accepted.
    Wait { seconds: i64 },
}

/// The triplet, normalised.
///
/// The address is normalised by the caller — an IPv4-mapped IPv6 form and its
/// plain form are one host, and two rows for it would be two delays. The
/// addresses are folded on the domain only, matching the rest of the project:
/// the local part belongs to the destination host.
pub fn normalise(
    address: std::net::IpAddr,
    sender: &str,
    recipient: &str,
) -> (String, String, String) {
    (
        address.to_canonical().to_string(),
        fold_domain(sender),
        fold_domain(recipient),
    )
}

fn fold_domain(address: &str) -> String {
    match address.rsplit_once('@') {
        Some((local, domain)) => format!("{local}@{}", domain.to_ascii_lowercase()),
        None => address.to_string(),
    }
}

/// Decide, and record the attempt.
///
/// One statement per outcome and no transaction: the two writes are idempotent
/// and independent, and a crash between them costs at most one extra delay —
/// which is the failure this is allowed to have. Holding a transaction open
/// across a `RCPT` decision would put the acceptance path behind the queue's
/// writer for every recipient of every message.
pub fn check(
    conn: &Connection,
    address: std::net::IpAddr,
    sender: &str,
    recipient: &str,
    delay_seconds: i64,
    now: i64,
) -> rusqlite::Result<Verdict> {
    if delay_seconds <= 0 {
        return Ok(Verdict::Pass);
    }

    let (address, sender, recipient) = normalise(address, sender, recipient);

    let seen: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT first_seen, passed_at FROM greylist
              WHERE address = ?1 AND sender = ?2 AND recipient = ?3",
            rusqlite::params![address, sender, recipient],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    match seen {
        // Never seen: remember it and ask them to come back.
        None => {
            conn.execute(
                "INSERT INTO greylist(address, sender, recipient, first_seen, last_seen)
                 VALUES(?1, ?2, ?3, ?4, ?4)",
                rusqlite::params![address, sender, recipient, now],
            )?;
            Ok(Verdict::Wait {
                seconds: delay_seconds,
            })
        }

        // Already admitted: nothing more to prove, ever.
        Some((_, Some(_))) => {
            conn.execute(
                "UPDATE greylist SET last_seen = ?4
                  WHERE address = ?1 AND sender = ?2 AND recipient = ?3",
                rusqlite::params![address, sender, recipient, now],
            )?;
            Ok(Verdict::Pass)
        }

        // Seen, not yet admitted. The delay is measured from the first attempt,
        // so a sender that retries promptly waits once — not once per retry.
        Some((first_seen, None)) => {
            let waited = now - first_seen;
            if waited >= delay_seconds {
                conn.execute(
                    "UPDATE greylist SET passed_at = ?4, last_seen = ?4
                      WHERE address = ?1 AND sender = ?2 AND recipient = ?3",
                    rusqlite::params![address, sender, recipient, now],
                )?;
                Ok(Verdict::Pass)
            } else {
                conn.execute(
                    "UPDATE greylist SET last_seen = ?4
                      WHERE address = ?1 AND sender = ?2 AND recipient = ?3",
                    rusqlite::params![address, sender, recipient, now],
                )?;
                Ok(Verdict::Wait {
                    seconds: delay_seconds - waited,
                })
            }
        }
    }
}

/// Forget triplets nobody has used for a while.
///
/// Measured from `last_seen`, so an active sender is never forgotten and a
/// sender that stopped is eventually made to prove itself again. Without this
/// the table is a permanent record of everyone who has ever tried to send here,
/// which is both unbounded and more information than the machine needs to keep.
pub fn forget_idle(conn: &Connection, retain_seconds: i64, now: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM greylist WHERE last_seen < ?1",
        [now - retain_seconds],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../pigeon-db/migrations/0006_greylist.sql"))
            .unwrap();
        let _ = &mut conn;
        conn
    }

    const ADDR: fn() -> std::net::IpAddr = || "192.0.2.10".parse().unwrap();

    #[test]
    fn a_new_triplet_waits_and_the_retry_passes() {
        let conn = db();

        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "hello@example.com",
                60,
                1_000
            )
            .unwrap(),
            Verdict::Wait { seconds: 60 },
            "a first attempt was not delayed"
        );

        // A retry inside the delay waits for what is left, not for the whole
        // delay again — otherwise a sender that retries every 30s never gets in.
        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "hello@example.com",
                60,
                1_030
            )
            .unwrap(),
            Verdict::Wait { seconds: 30 }
        );

        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "hello@example.com",
                60,
                1_060
            )
            .unwrap(),
            Verdict::Pass,
            "a retry after the delay was still refused"
        );
    }

    #[test]
    fn an_admitted_triplet_is_never_delayed_again() {
        // The delay is a one-off cost. Charging it per message would be a
        // permanent tax for a benefit collected once.
        let conn = db();
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_000,
        )
        .unwrap();
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_060,
        )
        .unwrap();

        for at in [2_000, 90_000, 900_000] {
            assert_eq!(
                check(&conn, ADDR(), "a@remote.test", "hello@example.com", 60, at).unwrap(),
                Verdict::Pass
            );
        }
    }

    #[test]
    fn the_triplet_is_the_key_and_case_folds_the_domain_only() {
        let conn = db();
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_000,
        )
        .unwrap();

        // Same sender, different recipient: a separate first attempt, because
        // the pair is what was vouched for.
        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "sales@example.com",
                60,
                1_060
            )
            .unwrap(),
            Verdict::Wait { seconds: 60 }
        );

        // The domain folds, so a sender varying its case does not get a fresh
        // delay-free identity...
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_060,
        )
        .unwrap();
        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@REMOTE.test",
                "hello@EXAMPLE.com",
                60,
                1_070
            )
            .unwrap(),
            Verdict::Pass
        );

        // ...but the local part does not fold: `Hello@` is a different mailbox,
        // and treating it as the same one would admit an address nobody
        // vouched for.
        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "Hello@example.com",
                60,
                1_070
            )
            .unwrap(),
            Verdict::Wait { seconds: 60 }
        );
    }

    #[test]
    fn an_ipv4_mapped_address_is_the_same_client() {
        // Otherwise a client reaching a dual-stack listener would be delayed
        // once per form, which is a delay it can never work through.
        let conn = db();
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_000,
        )
        .unwrap();

        let mapped: std::net::IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        assert_eq!(
            check(
                &conn,
                mapped,
                "a@remote.test",
                "hello@example.com",
                60,
                1_060
            )
            .unwrap(),
            Verdict::Pass,
            "the mapped form was treated as a different client"
        );
    }

    #[test]
    fn a_zero_delay_is_off_rather_than_instant() {
        // Off means no rows written at all: a disabled feature that still
        // records every sender is a database growing for nothing.
        let conn = db();
        assert_eq!(
            check(
                &conn,
                ADDR(),
                "a@remote.test",
                "hello@example.com",
                0,
                1_000
            )
            .unwrap(),
            Verdict::Pass
        );
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM greylist", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "a disabled greylist still recorded a triplet");
    }

    #[test]
    fn idle_triplets_are_forgotten_and_active_ones_are_not() {
        let conn = db();
        check(
            &conn,
            ADDR(),
            "a@remote.test",
            "hello@example.com",
            60,
            1_000,
        )
        .unwrap();
        check(
            &conn,
            "198.51.100.4".parse().unwrap(),
            "b@remote.test",
            "hello@example.com",
            60,
            5_000,
        )
        .unwrap();

        // Measured from `last_seen`, so the one still in use survives.
        assert_eq!(forget_idle(&conn, 1_000, 5_500).unwrap(), 1);
        let left: String = conn
            .query_row("SELECT sender FROM greylist", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, "b@remote.test");
    }
}
