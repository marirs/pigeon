//! Publishing snapshots, and the concurrency model around them.
//!
//! Design: `M1-SNAPSHOT.md` §8.

use std::sync::{Arc, RwLock};

use crate::snapshot::Snapshot;

/// Holds the live routing table.
///
/// One writer — the daemon — and many concurrent readers on the SMTP path. A
/// reader clones the `Arc` out under the read lock and then works on its own
/// handle, so the critical section is a single atomic increment. That is why
/// this is not worth an `arc-swap` dependency.
#[derive(Debug, Default)]
pub struct Router {
    current: RwLock<Arc<Snapshot>>,
}

impl Router {
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    /// Take the snapshot for one **mail transaction**.
    ///
    /// A transaction is `MAIL FROM` through the end of `DATA`, or through
    /// `RSET`, and that is exactly the span over which a routing decision has
    /// to stay consistent: `RCPT TO` accepts a recipient against the table and
    /// the forwarding decision uses it again later. If a reload landed in
    /// between, a message could be accepted under one configuration and
    /// delivered under another — which for a removed recipient means accepting
    /// mail with nowhere to put it, and Pigeon keeps no copy.
    ///
    /// **Not per connection.** The session cap is an hour and a client may send
    /// many messages inside it, so pinning for the connection would let a
    /// session opened before a reload keep routing against a configuration the
    /// operator has already replaced — with no way to tell which connections
    /// are stale. The next `MAIL FROM` takes a fresh handle.
    pub fn for_transaction(&self) -> Arc<Snapshot> {
        Arc::clone(&self.current.read().expect("router lock poisoned"))
    }

    /// Install a snapshot. **Crate-private, and deliberately.**
    ///
    /// An earlier version of this was public, with a comment claiming there was
    /// "no way to publish an unvalidated table because there is no way to
    /// obtain one". That was false: [`Snapshot`] is `Default` and `Clone`, so
    /// any caller could construct one and publish it — before a commit, or
    /// without one at all, which is exactly the ordering [`crate::mutate`]
    /// exists to prevent.
    ///
    /// The guarantee is visibility, not the type. `mutate` is the only caller,
    /// and it calls this after the commit. Code outside the crate that wants a
    /// table published goes through `mutate`, and therefore through the
    /// validation and the transaction.
    ///
    /// [`Router::new`] stays public and takes any snapshot, which is not the
    /// same hole: it seeds a router that is not yet serving, and there is no
    /// commit for it to run ahead of.
    ///
    /// A single pointer store, so a reader sees the old table or the new one
    /// and never a partial one.
    pub(crate) fn publish(&self, snapshot: Snapshot) {
        *self.current.write().expect("router lock poisoned") = Arc::new(snapshot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{AliasInput, Destination, DomainInput};
    use pigeon_types::{Address, DomainGate, DomainStatus};

    fn table(local: &str, to: &str) -> Snapshot {
        let (dl, dd) = to.rsplit_once('@').unwrap();
        Snapshot::build(vec![DomainInput {
            name: "example.com".into(),
            gate: DomainGate {
                status: DomainStatus::Active,
                inbound_enabled: true,
                outbound_enabled: false,
            },
            plus_addressing: true,
            default_destination: None,
            aliases: vec![AliasInput {
                pattern: local.into(),
                reject: false,
                destinations: vec![Destination {
                    local: dl.into(),
                    domain: dd.into(),
                }],
            }],
            catchall: None,
        }])
        .expect("build")
        .snapshot
    }

    fn first_destination(snap: &Snapshot, address: &str) -> Option<String> {
        let a = Address::parse(address).unwrap();
        match snap.resolve(&a) {
            crate::snapshot::Decision::Forward { destinations, .. } => {
                Some(destinations[0].to_string())
            }
            _ => None,
        }
    }

    #[test]
    fn a_published_table_is_visible_to_the_next_transaction() {
        let router = Router::new(table("hello", "old@x.test"));
        assert_eq!(
            first_destination(&router.for_transaction(), "hello@example.com").as_deref(),
            Some("old@x.test")
        );

        router.publish(table("hello", "new@x.test"));
        assert_eq!(
            first_destination(&router.for_transaction(), "hello@example.com").as_deref(),
            Some("new@x.test")
        );
    }

    #[test]
    fn a_transaction_keeps_its_table_across_a_reload() {
        // Correctness, not performance. RCPT TO accepts a recipient against the
        // table and the forwarding decision uses it again later; if a reload
        // landed in between, a message could be accepted under one
        // configuration and delivered under another — which for a removed
        // recipient means accepting mail with nowhere to put it, and Pigeon
        // keeps no copy.
        let router = Router::new(table("hello", "old@x.test"));

        // MAIL FROM: the transaction takes its handle.
        let pinned = router.for_transaction();

        // The operator reloads mid-transaction, removing the recipient.
        router.publish(Snapshot::default());

        // RCPT TO, and later the delivery decision, both still see the table
        // the transaction started with.
        assert_eq!(
            first_destination(&pinned, "hello@example.com").as_deref(),
            Some("old@x.test"),
            "a reload changed the routing table underneath an open transaction"
        );

        // And the *next* transaction sees the new one, so a long-lived
        // connection cannot keep routing against a replaced configuration.
        assert_eq!(
            first_destination(&router.for_transaction(), "hello@example.com"),
            None,
            "a fresh transaction did not pick up the reload"
        );
    }

    #[test]
    fn concurrent_readers_and_a_writer_do_not_deadlock_or_tear() {
        // The critical section is one Arc clone. This is not a performance
        // assertion — it is that a reader never observes a partial table.
        use std::sync::Arc;
        use std::thread;

        let router = Arc::new(Router::new(table("hello", "a@x.test")));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let r = Arc::clone(&router);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let snap = r.for_transaction();
                        // Whatever it is, it is one whole table.
                        if let Some(d) = first_destination(&snap, "hello@example.com") {
                            assert!(d == "a@x.test" || d == "b@x.test", "torn read: {d}");
                        }
                    }
                })
            })
            .collect();

        for i in 0..200 {
            router.publish(table(
                "hello",
                if i % 2 == 0 { "a@x.test" } else { "b@x.test" },
            ));
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for r in readers {
            r.join().expect("reader panicked");
        }
    }
}
