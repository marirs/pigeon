//! The mutation contract, asserted step by step.
//!
//! ```text
//! 1. apply  2. validate inside the transaction  3. roll back  4. commit  5. publish
//! ```
//!
//! Each of these tests fails if one step moves. That matters more than usual
//! here: every step is ordered against a specific way of losing or corrupting
//! configuration, and none of the orderings is obviously wrong from the code.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pigeon_db::repo::{self, Address, AliasKind};
use pigeon_route::{Decision, Router, Snapshot};
use pigeon_types::Address as ParsedAddress;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "pigeon-mutate-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn db(&self) -> PathBuf {
        self.0.join("pigeon.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A migrated database, a router, and a domain that is carrying mail.
fn ready(tag: &str) -> (TempDir, rusqlite::Connection, Router) {
    let tmp = TempDir::new(tag);
    let mut conn = pigeon_db::open(&tmp.db()).expect("open");
    pigeon_db::migrate(&mut conn, &tmp.db()).expect("migrate");

    let me = Address::parse("me@example.net").unwrap();
    repo::add_domain(&conn, "example.com", Some(&me)).expect("add domain");
    conn.execute("UPDATE domain SET status = 'active'", [])
        .expect("activate");

    let router = Router::new(
        Snapshot::build(pigeon_route::load(&conn).unwrap())
            .unwrap()
            .snapshot,
    );
    (tmp, conn, router)
}

fn routes_to(router: &Router, address: &str) -> Option<String> {
    let snap = router.for_transaction();
    let a = ParsedAddress::parse(address).unwrap();
    match snap.resolve(&a) {
        Decision::Forward { destinations, .. } => Some(destinations[0].to_string()),
        _ => None,
    }
}

fn alias_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM alias", [], |r| r.get(0))
        .unwrap()
}

// ------------------------------------------------------------ the happy path

#[test]
fn a_valid_mutation_commits_and_publishes() {
    let (_t, mut conn, router) = ready("ok");
    assert_eq!(routes_to(&router, "hello@example.com"), None);

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(tx, "example.com", "hello", AliasKind::Forward, &[])
    })
    .expect("mutation");

    // Step 4: the row is committed.
    assert_eq!(alias_count(&conn), 1);
    // Step 5: and the router serves it.
    assert_eq!(
        routes_to(&router, "hello@example.com").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn reports_come_back_from_a_successful_mutation() {
    // A redundant alias routes correctly and is probably not what was wanted,
    // so it is said rather than refused.
    let (_t, mut conn, router) = ready("reports");
    let me = Address::parse("me@example.net").unwrap();
    repo::set_catchall(&conn, "example.com", Some(&me)).unwrap();

    let outcome = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&me),
        )
    })
    .expect("mutation");

    assert!(
        outcome
            .reports
            .iter()
            .any(|r| matches!(r, pigeon_route::Report::RedundantAgainstCatchAll { .. })),
        "{:?}",
        outcome.reports
    );
}

// -------------------------------------------------- step 2 and 3: rollback

#[test]
fn a_mutation_that_would_break_routing_changes_nothing() {
    // The alias is written, the snapshot is built from the transaction, the
    // build refuses it, and the write goes with it. Nothing here is checked by
    // the repository — `add_alias` does not know whether the domain has a
    // default, and should not.
    let (_t, mut conn, router) = ready("rollback");
    repo::set_default_destination(&conn, "example.com", None).unwrap();

    let before = alias_count(&conn);
    let err = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(tx, "example.com", "hello", AliasKind::Forward, &[])
    })
    .expect_err("an alias that resolves nowhere was accepted");

    assert!(
        matches!(err, pigeon_route::MutationError::Invalid(_)),
        "{err:?}"
    );
    assert_eq!(
        alias_count(&conn),
        before,
        "the rejected alias was left in the database"
    );
}

#[test]
fn a_loop_introduced_by_a_mutation_is_refused_before_it_commits() {
    // The case the whole contract exists for: a row that is individually legal
    // and makes the configuration as a whole unserveable. No CHECK can see it.
    let (_t, mut conn, router) = ready("loop");
    let back = Address::parse("hello@example.com").unwrap();

    let err = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&back),
        )
    })
    .expect_err("an alias forwarding to itself was accepted");

    assert!(
        matches!(err, pigeon_route::MutationError::Invalid(_)),
        "{err:?}"
    );
    assert_eq!(alias_count(&conn), 0);
}

#[test]
fn a_rejected_mutation_does_not_publish() {
    // Step 5 is after step 4. A published table that a failed commit means
    // nobody asked for is worse than a stale one.
    let (_t, mut conn, router) = ready("nopublish");
    repo::set_default_destination(&conn, "example.com", None).unwrap();
    router.publish(
        Snapshot::build(pigeon_route::load(&conn).unwrap())
            .unwrap()
            .snapshot,
    );

    let _ = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(tx, "example.com", "hello", AliasKind::Forward, &[])
    });

    assert_eq!(
        routes_to(&router, "hello@example.com"),
        None,
        "a refused mutation reached the routing table"
    );
}

#[test]
fn every_write_in_a_failed_mutation_rolls_back_together() {
    // A mutation is often several statements. Rolling back only the last one
    // would leave a half-applied change that nothing named.
    let (_t, mut conn, router) = ready("multi");
    let ok = Address::parse("ok@example.net").unwrap();

    let err = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "first",
            AliasKind::Forward,
            std::slice::from_ref(&ok),
        )?;
        repo::add_alias(
            tx,
            "example.com",
            "second",
            AliasKind::Forward,
            std::slice::from_ref(&ok),
        )?;
        // Legal as a row; makes the configuration unserveable.
        repo::add_alias(
            tx,
            "example.com",
            "third",
            AliasKind::Forward,
            &[Address::parse("third@example.com").unwrap()],
        )
    })
    .expect_err("a loop was accepted");

    assert!(
        matches!(err, pigeon_route::MutationError::Invalid(_)),
        "{err:?}"
    );
    assert_eq!(
        alias_count(&conn),
        0,
        "the first two aliases survived a rolled-back mutation"
    );
}

#[test]
fn an_error_from_the_mutation_itself_rolls_back_too() {
    let (_t, mut conn, router) = ready("apply-err");
    let ok = Address::parse("ok@example.net").unwrap();

    let err = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&ok),
        )?;
        // Duplicate pattern: the schema refuses it.
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&ok),
        )
    })
    .expect_err("a duplicate alias was accepted");

    assert!(matches!(err, pigeon_route::MutationError::Db(_)), "{err:?}");
    assert_eq!(alias_count(&conn), 0);
}

// -------------------------------------------------------------- dry run

#[test]
fn a_preview_validates_the_real_outcome_and_keeps_nothing() {
    let (_t, mut conn, router) = ready("preview");

    let outcome = pigeon_route::preview(&mut conn, |tx| {
        repo::add_alias(tx, "example.com", "hello", AliasKind::Forward, &[])
    })
    .expect("preview");
    let _ = outcome.value;

    assert_eq!(alias_count(&conn), 0, "a dry run wrote to the database");
    assert_eq!(
        routes_to(&router, "hello@example.com"),
        None,
        "a dry run published a table"
    );
}

#[test]
fn a_preview_reports_what_the_real_mutation_would_refuse() {
    // The point of applying-then-rolling-back rather than modelling the change:
    // the preview is of the actual outcome, so it cannot disagree with it.
    let (_t, mut conn, _router) = ready("preview-invalid");
    let back = Address::parse("hello@example.com").unwrap();

    let err = pigeon_route::preview(&mut conn, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&back),
        )
    })
    .expect_err("a preview of a loop reported success");

    assert!(
        matches!(err, pigeon_route::MutationError::Invalid(_)),
        "{err:?}"
    );
}

// --------------------------------------------------------- repository shape

#[test]
fn removing_a_domain_takes_its_aliases_and_frees_its_destinations() {
    let (_t, mut conn, router) = ready("remove");
    let other = Address::parse("other@example.net").unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&other),
        )
    })
    .unwrap();

    let impact = repo::removal_impact(&conn, "example.com").unwrap();
    assert_eq!(impact.aliases, 1);

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::remove_domain(tx, "example.com")
    })
    .unwrap();

    assert_eq!(alias_count(&conn), 0);
    // The mailbox nothing refers to any more is gone; nothing else is.
    let left: i64 = conn
        .query_row("SELECT count(*) FROM destination", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0, "an unreferenced destination was left behind");
}

#[test]
fn replacing_a_destination_moves_every_use_of_it() {
    let (_t, mut conn, router) = ready("replace");
    let old = Address::parse("old@previous.net").unwrap();
    let new = Address::parse("new@example.net").unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&old),
        )?;
        repo::add_alias(
            tx,
            "example.com",
            "b",
            AliasKind::Forward,
            std::slice::from_ref(&old),
        )?;
        repo::set_default_destination(tx, "example.com", Some(&old))
    })
    .unwrap();

    let outcome = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::replace_destination(tx, &old, &new, None)
    })
    .expect("replace");

    // Two aliases and the domain default.
    assert_eq!(outcome.value, 3);
    assert_eq!(
        routes_to(&router, "a@example.com").as_deref(),
        Some("new@example.net")
    );
    let remaining: i64 = conn
        .query_row(
            "SELECT count(*) FROM destination WHERE local = 'old'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0, "the replaced mailbox was left in the table");
}

#[test]
fn replacing_a_destination_can_be_narrowed_to_one_domain() {
    let (_t, mut conn, router) = ready("replace-scoped");
    let old = Address::parse("old@previous.net").unwrap();
    let new = Address::parse("new@example.net").unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_domain(tx, "other.test", Some(&old))?;
        repo::add_alias(
            tx,
            "example.com",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&old),
        )?;
        repo::add_alias(
            tx,
            "other.test",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&old),
        )
    })
    .unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::replace_destination(tx, &old, &new, Some("example.com"))
    })
    .expect("scoped replace");

    let aliases = repo::list_aliases(&conn, "other.test").unwrap();
    assert_eq!(
        aliases[0].destinations,
        vec!["old@previous.net".to_string()],
        "a scoped replace moved a destination on another domain"
    );
    let aliases = repo::list_aliases(&conn, "example.com").unwrap();
    assert_eq!(aliases[0].destinations, vec!["new@example.net".to_string()]);
}

#[test]
fn an_alias_that_already_points_at_the_new_mailbox_is_not_a_conflict() {
    // The primary key on (alias_id, destination_id) would refuse the duplicate.
    // "Already correct" has to be a no-op, not an error.
    let (_t, mut conn, router) = ready("replace-dup");
    let old = Address::parse("old@previous.net").unwrap();
    let new = Address::parse("new@example.net").unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(
            tx,
            "example.com",
            "both",
            AliasKind::Forward,
            &[old.clone(), new.clone()],
        )
    })
    .unwrap();

    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::replace_destination(tx, &old, &new, None)
    })
    .expect("replacing into a mailbox the alias already has");

    let aliases = repo::list_aliases(&conn, "example.com").unwrap();
    assert_eq!(aliases[0].destinations, vec!["new@example.net".to_string()]);
}

#[test]
fn a_catch_all_with_no_destination_to_inherit_is_refused_by_the_schema() {
    // The row-level guard, before the snapshot ever sees it. Both exist: this
    // one covers rows written through SQLite, the snapshot covers a database
    // that arrived some other way.
    let (_t, conn, _router) = ready("catchall");
    repo::set_default_destination(&conn, "example.com", None).unwrap();

    let err = repo::set_catchall(&conn, "example.com", None)
        .expect_err("a catch-all routing nowhere was accepted");
    assert!(
        matches!(err, pigeon_db::DbError::CatchAllNeedsDestination(_)),
        "{err:?}"
    );
}

#[test]
fn an_alias_pattern_keeps_the_case_it_was_typed_in_out_of_the_database() {
    // Folded on write, because Pigeon is the authority for an address it *is*.
    let (_t, mut conn, router) = ready("case");
    pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(tx, "Example.COM", "Hello", AliasKind::Forward, &[])
    })
    .expect("mutation");

    let aliases = repo::list_aliases(&conn, "example.com").unwrap();
    assert_eq!(aliases[0].pattern, "hello");
    assert_eq!(
        routes_to(&router, "HELLO@EXAMPLE.COM").as_deref(),
        Some("me@example.net")
    );
}

#[test]
fn a_reject_rule_cannot_be_given_destinations() {
    let (_t, conn, _router) = ready("reject");
    let to = Address::parse("me@example.net").unwrap();
    let err = repo::add_alias(&conn, "example.com", "no", AliasKind::Reject, &[to])
        .expect_err("a reject rule with destinations was accepted");
    assert!(
        matches!(err, pigeon_db::DbError::RejectWithDestinations(_)),
        "{err:?}"
    );
}

#[test]
fn a_commit_that_fails_after_validation_publishes_nothing() {
    // The ordering `publish` after `commit` exists for exactly this, and
    // nothing else in this file distinguishes the two orders: when the mutation
    // is valid the commit always succeeds, so publishing early looks identical.
    //
    // So the commit is made to fail deliberately. SQLite's commit hook can veto
    // one, which is a real mechanism rather than a test seam bolted onto the
    // contract — and a real commit can fail for duller reasons: a full disk, a
    // filesystem error, a deferred constraint.
    //
    // Publishing first would leave the router serving a configuration that the
    // database does not contain and nobody asked for, with nothing to notice
    // the disagreement until the next reload.
    let (_t, mut conn, router) = ready("commit-fails");

    conn.commit_hook(Some(|| true))
        .expect("install commit hook");

    let err = pigeon_route::mutate(&mut conn, &router, |tx| {
        repo::add_alias(tx, "example.com", "hello", AliasKind::Forward, &[])
    })
    .expect_err("a vetoed commit reported success");
    assert!(
        matches!(err, pigeon_route::MutationError::Sqlite(_)),
        "{err:?}"
    );

    conn.commit_hook::<fn() -> bool>(None).expect("remove hook");

    // The row did not land...
    assert_eq!(alias_count(&conn), 0, "a vetoed commit wrote a row");
    // ...so the routing table must not claim it did.
    assert_eq!(
        routes_to(&router, "hello@example.com"),
        None,
        "a snapshot was published for a change that never committed"
    );
}
