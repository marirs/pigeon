//! Reporting a failure to the sender, exactly once.

use pigeon_spool::accept::{Acceptance, Destination};
use pigeon_spool::dsn::{self, Enqueued};
use pigeon_spool::queue::{self, Outcome};
use pigeon_spool::{Spool, SpoolId};
use rusqlite::Connection;

struct Fixture {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
    conn: Connection,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-dsn-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut conn, &path).unwrap();
        Self { dir, path, conn }
    }

    fn spool(&self) -> Spool {
        Spool::new(self.dir.clone())
    }

    /// A message with two recipients that deduplicate onto one destination.
    fn accept(&mut self, spool: &str, return_path: &str, destinations: &[&str]) {
        let acceptance = Acceptance {
            spool_id: SpoolId::new(spool).unwrap(),
            return_path: return_path.into(),
            original_sender: "alice@remote.test".into(),
            size_bytes: 42,
            routing_revision: 1,
            routing_fingerprint: vec![0; 32],
            original_recipients: vec!["hello@example.com".into(), "sales@example.com".into()],
            destinations: destinations
                .iter()
                .map(|d| Destination {
                    address: (*d).to_string(),
                    from_recipients: vec![0, 1],
                })
                .collect(),
        };
        pigeon_spool::accept(&mut self.conn, &self.path, &[acceptance], 1000).unwrap();
    }

    /// Fail every delivery permanently, which is what makes a report owed.
    fn fail_all(&mut self) {
        let claims =
            queue::claim(&mut self.conn, "w", 300, 100, 1000, queue::random_token).unwrap();
        for c in &claims {
            queue::complete(
                &self.conn,
                c,
                &Outcome::Failed {
                    code: 550,
                    response: "5.1.1 No such user".into(),
                },
                1001,
            )
            .unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_failure_is_owed_and_carries_the_addresses_the_sender_wrote() {
    let mut f = Fixture::new("owed");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["mailbox@provider.example"],
    );
    f.fail_all();

    let owed = dsn::owed(&f.conn).unwrap();
    assert_eq!(owed.len(), 1);
    let report = &owed[0];
    assert_eq!(report.entries.len(), 1);
    assert_eq!(
        report.entries[0].original_recipients,
        vec!["hello@example.com", "sales@example.com"],
        "the report cannot name the addresses the sender wrote"
    );
    assert_eq!(report.entries[0].state, "failed");
    assert_eq!(report.entries[0].code, Some(550));
}

#[test]
fn a_message_with_no_return_path_owes_nothing() {
    // A null sender means the message was itself a bounce. Failing to deliver
    // a bounce is a double bounce, and the only correct action is to stop.
    let mut f = Fixture::new("null");
    f.accept("msg-a", "", &["mailbox@provider.example"]);
    f.fail_all();

    assert!(
        dsn::owed(&f.conn).unwrap().is_empty(),
        "a bounce that failed owes a report"
    );
}

#[tokio::test]
async fn a_report_is_queued_as_an_ordinary_message_with_a_null_sender() {
    let mut f = Fixture::new("queued");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["mailbox@provider.example"],
    );
    f.fail_all();
    let report = dsn::owed(&f.conn).unwrap().remove(0);

    let dsn_id = SpoolId::new("dsn-1").unwrap();
    f.spool().install(&dsn_id, &[b"report"]).await.unwrap();

    let queued = dsn::enqueue(
        &mut f.conn,
        &report,
        &dsn_id,
        6,
        // The *reversed* return path: the original sender, not the SRS address,
        // which would deliver the bounce back into Pigeon.
        "alice@remote.test",
        2000,
    )
    .unwrap();
    assert!(matches!(queued, Enqueued::Queued { .. }));

    let (return_path, destination): (String, String) = f
        .conn
        .query_row(
            "SELECT m.return_path, d.destination
               FROM message m JOIN delivery d ON d.message_id = m.id
              WHERE m.spool_id = 'dsn-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(return_path.is_empty(), "the report has a return path");
    assert_eq!(destination, "alice@remote.test");

    // And the failure is no longer owed, pointing at the report that covers it.
    let (notification, notified_by): (String, Option<i64>) = f
        .conn
        .query_row(
            "SELECT notification, notified_by FROM delivery WHERE id = ?1",
            [report.entries[0].delivery_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(notification, "enqueued");
    assert!(notified_by.is_some());
}

#[tokio::test]
async fn a_second_generator_is_superseded_rather_than_duplicating_the_report() {
    // Two generators reading the same owed set would each render a report and
    // each enqueue it: one failure, two bounces to the same person. The
    // transaction claims the exact rows it rendered, so the loser commits
    // nothing.
    let mut f = Fixture::new("race");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["mailbox@provider.example"],
    );
    f.fail_all();

    // Both read the same owed set, as two workers would.
    let first = dsn::owed(&f.conn).unwrap().remove(0);
    let second = dsn::owed(&f.conn).unwrap().remove(0);
    assert_eq!(
        first, second,
        "the two generators did not see the same work"
    );

    let spool = f.spool();
    let a = SpoolId::new("dsn-a").unwrap();
    let b = SpoolId::new("dsn-b").unwrap();
    spool.install(&a, &[b"report a"]).await.unwrap();
    spool.install(&b, &[b"report b"]).await.unwrap();

    assert!(matches!(
        dsn::enqueue(&mut f.conn, &first, &a, 8, "alice@remote.test", 2000).unwrap(),
        Enqueued::Queued { .. }
    ));
    assert_eq!(
        dsn::enqueue(&mut f.conn, &second, &b, 8, "alice@remote.test", 2000).unwrap(),
        Enqueued::Superseded,
        "the second generator enqueued a duplicate report"
    );

    // Nothing of the loser's survives in the database…
    let messages: i64 = f
        .conn
        .query_row(
            "SELECT count(*) FROM message WHERE spool_id = 'dsn-b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(messages, 0, "a superseded report left rows behind");

    // …and the caller removes its spool file, which is the other half.
    dsn::discard_uncommitted(&spool, &b).await.unwrap();
    assert!(!spool.path(&b).exists());
    assert!(spool.path(&a).exists(), "the winner's report was removed");
}

#[tokio::test]
async fn a_partially_claimed_set_is_superseded_whole() {
    // Two destinations, one already reported by somebody else. Reporting the
    // remaining one alone would be a second bounce for the same message, so
    // the whole set rolls back and the next pass renders what is still owed.
    let mut f = Fixture::new("partial");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["one@provider.example", "two@provider.example"],
    );
    f.fail_all();

    let report = dsn::owed(&f.conn).unwrap().remove(0);
    assert_eq!(report.entries.len(), 2);

    // Somebody else reports the first one.
    f.conn
        .execute(
            "UPDATE delivery SET notification='enqueued', notified_by=(SELECT id FROM message LIMIT 1)
              WHERE id = ?1",
            [report.entries[0].delivery_id],
        )
        .unwrap();

    let dsn_id = SpoolId::new("dsn-1").unwrap();
    f.spool().install(&dsn_id, &[b"report"]).await.unwrap();
    assert_eq!(
        dsn::enqueue(&mut f.conn, &report, &dsn_id, 6, "alice@remote.test", 2000).unwrap(),
        Enqueued::Superseded
    );

    // The one that was still owed stays owed, for the next pass.
    let notification: String = f
        .conn
        .query_row(
            "SELECT notification FROM delivery WHERE id = ?1",
            [report.entries[1].delivery_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(notification, "owed", "a rolled-back claim kept its mark");
}

// ------------------------------------------------------------------ retention

#[tokio::test]
async fn a_body_is_kept_while_a_report_is_still_owed() {
    // The report quotes the original headers, so the body outlives the
    // deliveries by as long as the reports take.
    let mut f = Fixture::new("retain");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["mailbox@provider.example"],
    );
    f.fail_all();

    let message_id: i64 = f
        .conn
        .query_row("SELECT id FROM message WHERE spool_id='msg-a'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        !dsn::body_may_be_removed(&f.conn, message_id).unwrap(),
        "the body was removable while a report was owed"
    );

    let report = dsn::owed(&f.conn).unwrap().remove(0);
    let dsn_id = SpoolId::new("dsn-1").unwrap();
    f.spool().install(&dsn_id, &[b"report"]).await.unwrap();
    dsn::enqueue(&mut f.conn, &report, &dsn_id, 6, "alice@remote.test", 2000).unwrap();

    assert!(
        dsn::body_may_be_removed(&f.conn, message_id).unwrap(),
        "the body was still pinned after the report was queued"
    );
}

#[test]
fn a_body_is_kept_while_any_delivery_is_unfinished() {
    let mut f = Fixture::new("unfinished");
    f.accept(
        "msg-a",
        "SRS0=tag=AAA=remote.test=alice@pigeon.test",
        &["one@provider.example", "two@provider.example"],
    );

    let message_id: i64 = f
        .conn
        .query_row("SELECT id FROM message WHERE spool_id='msg-a'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!dsn::body_may_be_removed(&f.conn, message_id).unwrap());
}

// ---------------------------------------------------------------- abandoning

#[test]
fn a_report_with_nowhere_to_go_stops_being_owed_and_says_so() {
    // A return path that will not reverse is a local fault. Leaving it owed
    // would pin the body forever behind a notification that cannot happen.
    let mut f = Fixture::new("abandon");
    f.accept(
        "msg-a",
        "SRS0=broken@pigeon.test",
        &["mailbox@provider.example"],
    );
    f.fail_all();
    let report = dsn::owed(&f.conn).unwrap().remove(0);

    dsn::abandon_report(&f.conn, &report, "the return path does not verify", 3000).unwrap();

    let notification: String = f
        .conn
        .query_row(
            "SELECT notification FROM delivery WHERE id = ?1",
            [report.entries[0].delivery_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(notification, "none");

    // The reason is in the delivery log rather than only in a process log, so
    // "why did the sender hear nothing?" has an answer later.
    let response: String = f
        .conn
        .query_row(
            "SELECT response FROM delivery_event WHERE delivery_id = ?1 AND kind = 'notify'",
            [report.entries[0].delivery_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(response.contains("does not verify"), "{response}");
}

// ------------------------------------------------------------------ rendering

fn sample_report() -> pigeon_spool::dsn::Owed {
    pigeon_spool::dsn::Owed {
        message_id: 1,
        return_path: "SRS0=tag=AAA=remote.test=alice@pigeon.test".into(),
        original_sender: "alice@remote.test".into(),
        spool_id: SpoolId::new("msg-a").unwrap(),
        entries: vec![pigeon_spool::dsn::Entry {
            delivery_id: 1,
            destination: "mailbox@provider.example".into(),
            original_recipients: vec!["hello@example.com".into()],
            state: "failed".into(),
            code: Some(550),
            response: Some("5.1.1 No such user".into()),
        }],
    }
}

#[test]
fn a_report_names_the_address_the_sender_wrote() {
    // After forwarding, the destination that failed is a mailbox the sender
    // has never heard of. A report naming only that cannot be acted on.
    let rendered = pigeon_spool::report::render(
        &sample_report(),
        "pigeon.test",
        "alice@remote.test",
        Some("From: <alice@remote.test>\r\nSubject: hi"),
        "Mon, 1 Sep 2026 00:00:00 +0000",
        "boundary42",
    );
    let text = String::from_utf8(rendered).unwrap();

    assert!(
        text.contains("Original-Recipient: rfc822; hello@example.com"),
        "{text}"
    );
    assert!(
        text.contains("Final-Recipient: rfc822; mailbox@provider.example"),
        "{text}"
    );
    // And the human half names it too, because most people who open a bounce
    // are not reading the machine-readable section.
    assert!(text.contains("hello@example.com\r\n"), "{text}");
    assert!(text.contains("5.1.1 No such user"), "{text}");
}

#[test]
fn a_report_returns_headers_and_never_the_body() {
    // Returning the body doubles the traffic an attacker gets from one message
    // and returns content to an address that may not have sent it.
    let rendered = pigeon_spool::report::render(
        &sample_report(),
        "pigeon.test",
        "alice@remote.test",
        pigeon_spool::report::headers_of(b"From: <a@b.test>\r\nSubject: hi\r\n\r\nsecret body")
            .as_deref(),
        "Mon, 1 Sep 2026 00:00:00 +0000",
        "boundary42",
    );
    let text = String::from_utf8(rendered).unwrap();

    assert!(text.contains("Content-Type: text/rfc822-headers"), "{text}");
    assert!(text.contains("Subject: hi"), "{text}");
    assert!(
        !text.contains("secret body"),
        "the original body was returned:\n{text}"
    );
}

#[test]
fn a_missing_original_is_described_rather_than_hidden() {
    // Omitting the headers silently would imply the message had none. The
    // fault is local, and the report says so rather than leaving the sender to
    // conclude something about their own message or their recipient.
    let rendered = pigeon_spool::report::render(
        &sample_report(),
        "pigeon.test",
        "alice@remote.test",
        None,
        "Mon, 1 Sep 2026 00:00:00 +0000",
        "boundary42",
    );
    let text = String::from_utf8(rendered).unwrap();

    assert!(!text.contains("text/rfc822-headers"), "{text}");
    assert!(
        text.contains("could not read its own stored copy"),
        "a missing original was hidden:\n{text}"
    );
    assert!(
        text.contains("fault here, not with your message"),
        "the local fault was blamed on the sender or the recipient:\n{text}"
    );
}

#[test]
fn giving_up_reads_differently_from_being_refused() {
    // An operator reading "we gave up after five days" and one reading "the
    // mailbox does not exist" need different actions, so the report does not
    // flatten them into one sentence or one status code.
    let mut expired = sample_report();
    expired.entries[0].state = "expired".into();
    expired.entries[0].code = None;
    expired.entries[0].response = Some("connection timed out".into());

    let text = String::from_utf8(pigeon_spool::report::render(
        &expired,
        "pigeon.test",
        "alice@remote.test",
        None,
        "Mon, 1 Sep 2026 00:00:00 +0000",
        "b",
    ))
    .unwrap();

    assert!(text.contains("gave up"), "{text}");
    assert!(text.contains("Status: 4.4.7"), "{text}");
    assert!(!text.contains("refused it permanently"), "{text}");
}

#[test]
fn a_local_failure_is_not_reported_as_the_recipients_fault() {
    // No SMTP code means nothing remote said anything. A 5.x.x status here
    // would tell the sender their recipient rejected the message.
    let mut local = sample_report();
    local.entries[0].code = None;
    local.entries[0].response = Some("local integrity failure: file missing".into());

    let text = String::from_utf8(pigeon_spool::report::render(
        &local,
        "pigeon.test",
        "alice@remote.test",
        None,
        "Mon, 1 Sep 2026 00:00:00 +0000",
        "b",
    ))
    .unwrap();

    assert!(text.contains("Status: 4.3.0"), "{text}");
    assert!(text.contains("Diagnostic-Code: x-local;"), "{text}");
}
