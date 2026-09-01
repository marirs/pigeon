//! What `RCPT TO` decided, carried to the end of `DATA`.
//!
//! Routing happens **once**, at `RCPT TO`, against the runtime pinned for the
//! transaction. `DATA` consumes what was decided; it does not ask the router
//! again, even against the same runtime. Two lookups are two answers waiting to
//! differ — from a rule the second lookup reads differently, from a plus-tag
//! stripped one way and not the other, from an ordering that changed — and the
//! answer the sender was given a `250` for is the first one.
//!
//! The plan records the decision per recipient rather than an assembled result,
//! because the SMTP session has the last word on which recipients the envelope
//! ends up holding: a recipient this sink accepts can still be refused by the
//! recipient cap immediately afterwards. Grouping from the envelope at `DATA`
//! is therefore reading stored decisions, not making new ones — a recipient
//! with no stored decision is a bug, and is treated as one.

use std::collections::HashMap;

use pigeon_route::{Decision, Snapshot};
use pigeon_types::Address;

/// Everything routing decided for one mail transaction.
#[derive(Debug, Default)]
pub struct Plan {
    /// Decisions in the order the recipients were accepted.
    ///
    /// A `Vec` rather than a map: a transaction holds at most the recipient cap
    /// — a few hundred — and the order is what makes grouping deterministic.
    decided: Vec<(String, Resolved)>,
}

/// Where one accepted recipient goes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolved {
    /// The managed domain the mail was accepted **for**, folded.
    ///
    /// The identity Pigeon forwards under and signs with, which is why it is
    /// the grouping key (R-2) and not merely a label.
    domain: String,
    /// Resolved destinations, as the routing table gave them.
    destinations: Vec<String>,
}

/// Why a recipient was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A rule refuses it, nothing routes it, or the domain is not carried here.
    /// Permanent: no configuration in force will deliver this address.
    NoSuchUser,
    /// The domain is carried but is not accepting: gated by DNS, or switched
    /// off by the operator. Transient, because the address is real and the
    /// gate is expected to open — refusing permanently would tell the sender
    /// to give up on a mailbox that is about to work.
    NotAccepting,
}

impl Plan {
    /// Route one recipient and record the result.
    ///
    /// The address is stored as the sender wrote it, because that is what a
    /// DSN has to name and what `original_recipient` records.
    pub fn route(&mut self, snapshot: &Snapshot, address: &str) -> Result<(), Refusal> {
        let Ok(parsed) = Address::parse(address) else {
            // The server only consults routing for an address it has already
            // parsed, so this is unreachable in the daemon. Answered rather
            // than asserted: a caller that stopped checking should refuse mail,
            // not panic a connection handler.
            return Err(Refusal::NoSuchUser);
        };

        // A repeat is not a second decision. The session accepts a repeated
        // `RCPT` and records the address once, so grouping would ignore the
        // extra entries — but nothing caps how many times a client may repeat
        // one address, and a plan that grew per repeat would be memory a
        // connection can consume for free.
        if self.lookup(&parsed).is_some() {
            return Ok(());
        }

        match snapshot.resolve(&parsed) {
            Decision::Forward { destinations, .. } => {
                self.decided.push((
                    address.to_string(),
                    Resolved {
                        domain: parsed.domain().to_ascii_lowercase(),
                        destinations: destinations.iter().map(ToString::to_string).collect(),
                    },
                ));
                Ok(())
            }
            Decision::DomainNotAccepting => Err(Refusal::NotAccepting),
            Decision::Reject { .. } | Decision::NoRoute | Decision::UnknownDomain => {
                Err(Refusal::NoSuchUser)
            }
        }
    }

    /// How many decisions are held. A repeat must not add one.
    #[cfg(test)]
    fn decisions(&self) -> usize {
        self.decided.len()
    }

    fn lookup(&self, address: &Address<'_>) -> Option<&Resolved> {
        self.decided.iter().find_map(|(recorded, resolved)| {
            Address::parse(recorded)
                .ok()
                .filter(|r| r.same_mailbox(address))
                .map(|_| resolved)
        })
    }

    /// Assemble the accepted recipients into one group per managed domain.
    ///
    /// `recipients` is the envelope as the session finally holds it, which is
    /// authoritative: a recipient routed here and then refused by the recipient
    /// cap was never acknowledged, and must not become a delivery.
    ///
    /// Fails on a recipient with no stored decision rather than routing it.
    /// That combination means the session acknowledged an address this sink
    /// never accepted, which is a bug in the wiring — and the safe answer to a
    /// bug at this point is a transient failure, not a guess about where
    /// somebody's mail should go.
    pub fn groups(&self, recipients: &[String]) -> Result<Vec<Group>, Undecided> {
        let mut groups: Vec<Group> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();

        for recipient in recipients {
            let parsed = Address::parse(recipient).map_err(|_| Undecided {
                recipient: recipient.clone(),
            })?;
            let resolved = self.lookup(&parsed).ok_or_else(|| Undecided {
                recipient: recipient.clone(),
            })?;

            let at = *index.entry(resolved.domain.clone()).or_insert_with(|| {
                groups.push(Group {
                    domain: resolved.domain.clone(),
                    recipients: Vec::new(),
                    destinations: Vec::new(),
                });
                groups.len() - 1
            });

            let group = &mut groups[at];
            let from = group.recipients.len();
            group.recipients.push(recipient.clone());

            for destination in &resolved.destinations {
                group.add_destination(destination, from);
            }
        }

        Ok(groups)
    }
}

/// One managed domain's share of a submission: R-2's split.
///
/// Its own bytes, its own signing identity, its own spool file and its own
/// `message` row — because the signing identity is a property of the domain the
/// mail was accepted for, and one set of bytes cannot carry two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub domain: String,
    /// The addresses the sender wrote, in envelope order.
    pub recipients: Vec<String>,
    /// Deduplicated destinations, each with the recipients that led to it.
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub address: String,
    /// Indexes into [`Group::recipients`].
    pub from_recipients: Vec<usize>,
}

impl Group {
    /// Add a destination, merging it with an equal one already present.
    ///
    /// Deduplicated **within** a group and never across groups (R-2): two
    /// recipients on one domain reaching one mailbox is one delivery, while
    /// two recipient *domains* reaching that mailbox is two, because the sender
    /// addressed two recipients and the two relay forms are signed under
    /// different identities.
    ///
    /// Every original recipient is kept on the merged row, so a failure is
    /// reported against each address the sender actually wrote.
    fn add_destination(&mut self, address: &str, from: usize) {
        let parsed = Address::parse(address).ok();

        for existing in &mut self.destinations {
            let same = match (&parsed, Address::parse(&existing.address).ok()) {
                // Folds the domain only. The local part belongs to the
                // destination host, so `Bob@x` and `bob@x` are two mailboxes.
                (Some(a), Some(b)) => a.same_mailbox(&b),
                // Unparseable destinations cannot be compared as mailboxes, so
                // they are compared as bytes rather than being merged blindly.
                _ => existing.address == address,
            };
            if same {
                if !existing.from_recipients.contains(&from) {
                    existing.from_recipients.push(from);
                }
                return;
            }
        }

        self.destinations.push(Destination {
            address: address.to_string(),
            from_recipients: vec![from],
        });
    }
}

/// An acknowledged recipient that routing never decided.
#[derive(Debug, thiserror::Error)]
#[error("no routing decision was recorded for {recipient}")]
pub struct Undecided {
    pub recipient: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pigeon_route::snapshot::{AliasInput, CatchAllInput, DomainInput, Forwarding};
    use pigeon_types::{DomainGate, DomainStatus, ForwardPolicy};

    fn destination(local: &str, domain: &str) -> pigeon_route::snapshot::Destination {
        pigeon_route::snapshot::Destination {
            local: local.into(),
            domain: domain.into(),
        }
    }

    fn domain(name: &str, default: &str) -> DomainInput {
        let (local, host) = default.rsplit_once('@').unwrap();
        DomainInput {
            name: name.into(),
            gate: DomainGate {
                status: DomainStatus::Active,
                inbound_enabled: true,
                outbound_enabled: false,
            },
            plus_addressing: true,
            forwarding: Forwarding {
                policy: ForwardPolicy::Preserve,
                dkim: None,
            },
            default_destination: Some(destination(local, host)),
            aliases: Vec::new(),
            // A catch-all so an address with no alias of its own still routes:
            // a domain default is what an alias *inherits*, not a rule.
            catchall: Some(CatchAllInput { destination: None }),
        }
    }

    fn snapshot(domains: Vec<DomainInput>) -> Snapshot {
        Snapshot::build(domains)
            .expect("the fixture should build")
            .snapshot
    }

    /// Route each address in turn, as `RCPT TO` would.
    fn plan(snapshot: &Snapshot, addresses: &[&str]) -> (Plan, Vec<Result<(), Refusal>>) {
        let mut plan = Plan::default();
        let outcomes = addresses
            .iter()
            .map(|a| plan.route(snapshot, a))
            .collect::<Vec<_>>();
        (plan, outcomes)
    }

    #[test]
    fn a_recipient_is_routed_once_and_read_back() {
        let s = snapshot(vec![{
            let mut d = domain("example.com", "me@example.net");
            d.aliases = vec![AliasInput {
                pattern: "hello".into(),
                reject: false,
                destinations: vec![destination("inbox", "example.net")],
            }];
            d
        }]);

        let (plan, outcomes) = plan(&s, &["hello@example.com"]);
        assert_eq!(outcomes, vec![Ok(())]);

        let groups = plan.groups(&["hello@example.com".into()]).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].domain, "example.com");
        assert_eq!(groups[0].recipients, vec!["hello@example.com".to_string()]);
        assert_eq!(
            groups[0].destinations,
            vec![Destination {
                address: "inbox@example.net".into(),
                from_recipients: vec![0],
            }]
        );
    }

    #[test]
    fn every_precedence_tier_decides_at_rcpt() {
        // The tiers are the router's own tests. What is asserted here is that
        // each of them reaches the plan intact, because a decision that is
        // right and then dropped is the same outcome as a wrong one.
        let s = snapshot(vec![{
            let mut d = domain("example.com", "default@example.net");
            d.aliases = vec![
                AliasInput {
                    pattern: "hello".into(),
                    reject: false,
                    destinations: vec![destination("exact", "example.net")],
                },
                AliasInput {
                    pattern: "shop-*".into(),
                    reject: false,
                    destinations: vec![destination("wild", "example.net")],
                },
                AliasInput {
                    pattern: "refused".into(),
                    reject: true,
                    destinations: vec![],
                },
            ];
            d.catchall = Some(CatchAllInput {
                destination: Some(vec![destination("catch", "example.net")]),
            });
            d
        }]);

        let addresses = [
            "hello@example.com",
            "shop-42@example.com",
            "anything@example.com",
            "hello+github@example.com",
            "refused@example.com",
        ];
        let (plan, outcomes) = plan(&s, &addresses);
        assert_eq!(
            outcomes,
            vec![Ok(()), Ok(()), Ok(()), Ok(()), Err(Refusal::NoSuchUser)],
            "a precedence tier answered differently at RCPT"
        );

        let accepted: Vec<String> = addresses[..4].iter().map(|a| a.to_string()).collect();
        let groups = plan.groups(&accepted).unwrap();
        let where_to: Vec<&str> = groups[0]
            .destinations
            .iter()
            .map(|d| d.address.as_str())
            .collect();
        assert_eq!(
            where_to,
            vec![
                "exact@example.net",
                "wild@example.net",
                "catch@example.net",
                // Plus-addressing: the tag is stripped for the exact lookup, so
                // `hello+github` reaches `hello`'s destination — and merges
                // with it, because it is the same mailbox.
            ],
            "the tiers did not resolve where the router says they do"
        );
        assert_eq!(
            groups[0].destinations[0].from_recipients,
            vec![0, 3],
            "the plus-addressed recipient did not merge into the alias it names"
        );
    }

    #[test]
    fn a_gated_domain_is_refused_transiently() {
        // Gating is not "no such user": the address exists and the gate is
        // expected to open, so a permanent refusal would tell the sender to
        // give up on a mailbox that is about to work.
        let s = snapshot(vec![{
            let mut d = domain("example.com", "me@example.net");
            d.gate.inbound_enabled = false;
            d
        }]);
        let (_, outcomes) = plan(&s, &["hello@example.com"]);
        assert_eq!(outcomes, vec![Err(Refusal::NotAccepting)]);

        // And a domain that is not carried here at all is permanent.
        let (_, outcomes) = plan(&s, &["hello@elsewhere.example"]);
        assert_eq!(outcomes, vec![Err(Refusal::NoSuchUser)]);
    }

    #[test]
    fn recipients_reaching_one_mailbox_become_one_delivery() {
        // Deduplicated after expansion, with every original recipient kept: the
        // mailbox receives one copy, and a failure is still reported against
        // both addresses the sender wrote.
        let s = snapshot(vec![{
            let mut d = domain("example.com", "shared@example.net");
            d.aliases = vec![
                AliasInput {
                    pattern: "one".into(),
                    reject: false,
                    destinations: vec![destination("shared", "example.net")],
                },
                AliasInput {
                    pattern: "two".into(),
                    reject: false,
                    // The same mailbox with the domain cased differently, which
                    // folds, and a second mailbox that does not.
                    destinations: vec![
                        destination("shared", "EXAMPLE.NET"),
                        destination("other", "example.net"),
                    ],
                },
            ];
            d
        }]);

        let (plan, _) = plan(&s, &["one@example.com", "two@example.com"]);
        let groups = plan
            .groups(&["one@example.com".into(), "two@example.com".into()])
            .unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].destinations,
            vec![
                Destination {
                    address: "shared@example.net".into(),
                    from_recipients: vec![0, 1],
                },
                Destination {
                    address: "other@example.net".into(),
                    from_recipients: vec![1],
                },
            ]
        );
    }

    #[test]
    fn a_local_part_is_not_folded_when_destinations_are_compared() {
        // `Bob@x` and `bob@x` are different mailboxes: the local part belongs
        // to the destination host. Merging them would silently drop one.
        let s = snapshot(vec![{
            let mut d = domain("example.com", "me@example.net");
            d.aliases = vec![AliasInput {
                pattern: "both".into(),
                reject: false,
                destinations: vec![
                    destination("Bob", "example.net"),
                    destination("bob", "example.net"),
                ],
            }];
            d
        }]);

        let (plan, _) = plan(&s, &["both@example.com"]);
        let groups = plan.groups(&["both@example.com".into()]).unwrap();
        assert_eq!(groups[0].destinations.len(), 2, "two mailboxes became one");
    }

    #[test]
    fn each_managed_domain_becomes_its_own_group() {
        // R-2. Each group gets its own bytes and signing identity, so the
        // grouping is what the acceptance transaction is built from — and two
        // recipient domains reaching one mailbox is deliberately two
        // deliveries, not one.
        let s = snapshot(vec![
            domain("one.example", "shared@example.net"),
            domain("two.example", "shared@example.net"),
        ]);

        let recipients = vec![
            "a@one.example".to_string(),
            "b@two.example".to_string(),
            "c@one.example".to_string(),
        ];
        let mut plan = Plan::default();
        for r in &recipients {
            plan.route(&s, r).expect("every recipient routes");
        }

        let groups = plan.groups(&recipients).unwrap();
        assert_eq!(groups.len(), 2, "the submission did not split by domain");
        assert_eq!(groups[0].domain, "one.example");
        assert_eq!(groups[0].recipients, vec!["a@one.example", "c@one.example"]);
        assert_eq!(groups[1].domain, "two.example");
        assert_eq!(groups[1].recipients, vec!["b@two.example"]);

        // The same mailbox in both groups, deliberately not deduplicated.
        assert_eq!(groups[0].destinations[0].address, "shared@example.net");
        assert_eq!(groups[1].destinations[0].address, "shared@example.net");
    }

    #[test]
    fn a_repeated_recipient_is_one_decision() {
        // The session accepts a repeat and records the address once, so
        // grouping ignores the extra entries — but nothing caps how many times
        // a client may repeat one address, and a plan that grew per repeat
        // would be memory a connection can consume for free.
        let s = snapshot(vec![domain("example.com", "me@example.net")]);
        let mut repeated = vec!["hello@example.com", "hello@EXAMPLE.com"];
        repeated.extend(std::iter::repeat_n("hello@example.com", 500));

        let (plan, outcomes) = plan(&s, &repeated);
        assert!(outcomes.iter().all(Result::is_ok), "a repeat was refused");
        assert_eq!(plan.decisions(), 1, "a repeated address grew the plan");

        let groups = plan.groups(&["hello@example.com".into()]).unwrap();
        assert_eq!(groups[0].recipients.len(), 1);
        assert_eq!(groups[0].destinations[0].from_recipients, vec![0]);
    }

    #[test]
    fn a_recipient_the_session_refused_is_not_delivered() {
        // A recipient can be routed here and then refused by the session's
        // recipient cap. The envelope is what the sender was acknowledged for,
        // so a destination that only that recipient reached must not become a
        // delivery.
        let s = snapshot(vec![{
            let mut d = domain("example.com", "me@example.net");
            d.aliases = vec![
                AliasInput {
                    pattern: "kept".into(),
                    reject: false,
                    destinations: vec![destination("kept", "example.net")],
                },
                AliasInput {
                    pattern: "capped".into(),
                    reject: false,
                    destinations: vec![destination("capped", "example.net")],
                },
            ];
            d
        }]);

        let (plan, _) = plan(&s, &["kept@example.com", "capped@example.com"]);
        let groups = plan.groups(&["kept@example.com".into()]).unwrap();

        assert_eq!(groups[0].recipients, vec!["kept@example.com"]);
        assert_eq!(
            groups[0].destinations,
            vec![Destination {
                address: "kept@example.net".into(),
                from_recipients: vec![0],
            }],
            "a recipient the session never acknowledged became a delivery"
        );
    }

    #[test]
    fn an_undecided_recipient_is_a_failure_and_not_a_lookup() {
        // The rule that keeps `DATA` from routing: an acknowledged address with
        // no stored decision is a wiring bug, and the answer to a bug here is a
        // transient failure rather than a guess about where mail should go.
        let s = snapshot(vec![domain("example.com", "me@example.net")]);
        let (plan, _) = plan(&s, &["hello@example.com"]);

        let err = plan
            .groups(&[
                "hello@example.com".into(),
                "never-routed@example.com".into(),
            ])
            .expect_err("an unrouted recipient should not be resolvable");
        assert_eq!(err.recipient, "never-routed@example.com");
    }
}
