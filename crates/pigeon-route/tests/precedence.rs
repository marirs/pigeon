//! Acceptance tests for the routing snapshot.
//!
//! `M1-SNAPSHOT.md` §9 names thirteen ways to break the router, and every one
//! must turn at least one test here red. The routing table decides where mail
//! goes, and three rounds of `M0-FINDINGS.md` are about tests shaped to pass —
//! so these were written from the design document before the code, and each
//! names the property it defends rather than the code path it walks.

use pigeon_route::{
    AliasInput, BuildError, CatchAllInput, Decision, Destination, DomainInput, Report, Snapshot,
    Tier,
};
use pigeon_types::{Address, DomainGate, DomainStatus};

// ------------------------------------------------------------------- builders

fn dest(s: &str) -> Destination {
    let (local, domain) = s.rsplit_once('@').expect("test destination");
    Destination {
        local: local.to_string(),
        domain: domain.to_ascii_lowercase(),
    }
}

fn alias(pattern: &str, to: &[&str]) -> AliasInput {
    AliasInput {
        pattern: pattern.into(),
        reject: false,
        destinations: to.iter().map(|d| dest(d)).collect(),
    }
}

fn inheriting(pattern: &str) -> AliasInput {
    AliasInput {
        pattern: pattern.into(),
        reject: false,
        destinations: Vec::new(),
    }
}

fn reject(pattern: &str) -> AliasInput {
    AliasInput {
        pattern: pattern.into(),
        reject: true,
        destinations: Vec::new(),
    }
}

fn live() -> DomainGate {
    DomainGate {
        status: DomainStatus::Active,
        inbound_enabled: true,
        outbound_enabled: false,
    }
}

fn domain(name: &str, aliases: Vec<AliasInput>) -> DomainInput {
    DomainInput {
        name: name.into(),
        gate: live(),
        plus_addressing: true,
        default_destination: None,
        aliases,
        catchall: None,
    }
}

fn build(inputs: Vec<DomainInput>) -> Snapshot {
    Snapshot::build(inputs)
        .expect("configuration should build")
        .snapshot
}

/// Resolve, holding the address so the borrow in `Decision` stays alive.
fn route<'a>(snap: &'a Snapshot, address: &'a Address<'a>) -> Decision<'a> {
    snap.resolve(address)
}

fn addr(s: &str) -> Address<'_> {
    Address::parse(s).expect("test address")
}

fn forwarded_to(snap: &Snapshot, address: &str) -> Vec<String> {
    let a = addr(address);
    match route(snap, &a) {
        Decision::Forward { destinations, .. } => {
            destinations.iter().map(|d| d.to_string()).collect()
        }
        other => panic!("{address} was not forwarded: {other:?}"),
    }
}

fn tier_of(snap: &Snapshot, address: &str) -> Tier {
    let a = addr(address);
    match route(snap, &a) {
        Decision::Forward { tier, .. } | Decision::Reject { tier, .. } => tier,
        other => panic!("{address} matched no rule: {other:?}"),
    }
}

// ------------------------------------------------------------------ §2 tiers

#[test]
fn an_exact_alias_beats_a_wildcard() {
    let snap = build(vec![domain(
        "example.com",
        vec![
            alias("hello", &["exact@x.test"]),
            alias("hel*", &["wild@x.test"]),
        ],
    )]);
    assert_eq!(forwarded_to(&snap, "hello@example.com"), ["exact@x.test"]);
    assert_eq!(tier_of(&snap, "hello@example.com"), Tier::ExactFull);
}

#[test]
fn a_wildcard_beats_the_catch_all() {
    let mut d = domain("example.com", vec![alias("shop-*", &["shop@x.test"])]);
    d.catchall = Some(CatchAllInput {
        destination: Some(vec![dest("all@x.test")]),
    });
    let snap = build(vec![d]);
    assert_eq!(forwarded_to(&snap, "shop-1@example.com"), ["shop@x.test"]);
    assert_eq!(forwarded_to(&snap, "other@example.com"), ["all@x.test"]);
}

#[test]
fn the_most_literal_wildcard_wins() {
    // "Longest match", stated as the ranking key it actually is.
    let snap = build(vec![domain(
        "example.com",
        vec![
            alias("*", &["star@x.test"]),
            alias("shop-*", &["shop@x.test"]),
            alias("shop-old-*", &["old@x.test"]),
        ],
    )]);
    assert_eq!(
        forwarded_to(&snap, "shop-old-1@example.com"),
        ["old@x.test"]
    );
    assert_eq!(forwarded_to(&snap, "shop-1@example.com"), ["shop@x.test"]);
    assert_eq!(forwarded_to(&snap, "anything@example.com"), ["star@x.test"]);
}

#[test]
fn a_wildcard_reject_does_not_disable_a_more_specific_exact_alias() {
    // The precedence change approved in review. Under the original diagram,
    // reject was a tier and `hello` stopped working the moment `hell*` was
    // added — with the alias still listed and still looking correct.
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello", &["me@x.test"]), reject("hell*")],
    )]);
    assert_eq!(forwarded_to(&snap, "hello@example.com"), ["me@x.test"]);

    // And the reject still refuses everything no more specific rule claims.
    let a = addr("hellfire@example.com");
    assert!(matches!(route(&snap, &a), Decision::Reject { .. }));
}

#[test]
fn an_exact_reject_outranks_everything() {
    // Which is why "write it as an exact rule" is the answer for an address
    // that must never be accepted.
    let mut d = domain(
        "example.com",
        vec![reject("postmaster-old"), alias("*", &["all@x.test"])],
    );
    d.catchall = Some(CatchAllInput {
        destination: Some(vec![dest("all@x.test")]),
    });
    let snap = build(vec![d]);

    let a = addr("postmaster-old@example.com");
    assert!(matches!(route(&snap, &a), Decision::Reject { .. }));
}

// ------------------------------------------------------------- §4 plus tiers

#[test]
fn a_tagged_address_reaches_the_alias_its_base_names() {
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello", &["me@x.test"])],
    )]);
    assert_eq!(
        forwarded_to(&snap, "hello+github@example.com"),
        ["me@x.test"]
    );
    assert_eq!(tier_of(&snap, "hello+github@example.com"), Tier::ExactBase);
}

#[test]
fn a_tagged_address_can_have_its_own_alias() {
    // Stripping before matching would make this impossible.
    let snap = build(vec![domain(
        "example.com",
        vec![
            alias("hello", &["base@x.test"]),
            alias("hello+github", &["tagged@x.test"]),
        ],
    )]);
    assert_eq!(
        forwarded_to(&snap, "hello+github@example.com"),
        ["tagged@x.test"]
    );
    assert_eq!(tier_of(&snap, "hello+github@example.com"), Tier::ExactFull);
    assert_eq!(
        forwarded_to(&snap, "hello+other@example.com"),
        ["base@x.test"]
    );
}

#[test]
fn a_tagged_wildcard_matches_the_full_local_part() {
    // The bug review caught. An earlier order gave the full local part one
    // chance at the exact tier and used the base thereafter, so the wildcard
    // tier only ever saw `hello` — five characters, against a six-character
    // prefix — and `hello+*` matched nothing at all.
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello+*", &["tagged@x.test"])],
    )]);
    assert_eq!(
        forwarded_to(&snap, "hello+github@example.com"),
        ["tagged@x.test"]
    );
    assert_eq!(tier_of(&snap, "hello+github@example.com"), Tier::Wildcard);
}

#[test]
fn tagged_mail_on_a_catch_all_domain_still_finds_its_alias() {
    // Matching the full local part all the way down would send this to the
    // catch-all, because catch-all matches everything on the first pass.
    let mut d = domain("example.com", vec![alias("hello", &["me@x.test"])]);
    d.catchall = Some(CatchAllInput {
        destination: Some(vec![dest("all@x.test")]),
    });
    let snap = build(vec![d]);
    assert_eq!(
        forwarded_to(&snap, "hello+github@example.com"),
        ["me@x.test"]
    );
}

#[test]
fn plus_addressing_can_be_turned_off_per_domain() {
    let mut d = domain("example.com", vec![alias("hello", &["me@x.test"])]);
    d.plus_addressing = false;
    let snap = build(vec![d]);

    let a = addr("hello+github@example.com");
    assert!(
        matches!(route(&snap, &a), Decision::NoRoute),
        "the tag was stripped despite plus-addressing being off"
    );
}

#[test]
fn a_leading_plus_is_a_real_local_part() {
    let snap = build(vec![domain(
        "example.com",
        vec![alias("+tag", &["plus@x.test"])],
    )]);
    assert_eq!(forwarded_to(&snap, "+tag@example.com"), ["plus@x.test"]);
}

// ------------------------------------------------------------------ §1 case

#[test]
fn lookup_folds_case_on_both_halves() {
    let snap = build(vec![domain(
        "Example.COM",
        vec![alias("Hello", &["Me@Example.NET"])],
    )]);
    for written in [
        "hello@example.com",
        "HELLO@EXAMPLE.COM",
        "HeLLo@ExAmPle.Com",
    ] {
        assert_eq!(
            forwarded_to(&snap, written),
            ["Me@example.net"],
            "{written}"
        );
    }
}

#[test]
fn a_destination_keeps_the_case_it_was_given() {
    // RFC 5321 §2.4: the local part belongs to the destination host. Folding it
    // merges distinct recipients — finding 12.
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello", &["Bob.Smith@Example.NET"])],
    )]);
    assert_eq!(
        forwarded_to(&snap, "hello@example.com"),
        ["Bob.Smith@example.net"]
    );
}

// ----------------------------------------------------------- §5 inheritance

#[test]
fn an_alias_with_no_destinations_inherits_the_domain_default() {
    let mut d = domain(
        "example.com",
        vec![inheriting("hello"), alias("billing", &["finance@x.test"])],
    );
    d.default_destination = Some(dest("me@x.test"));
    let snap = build(vec![d]);

    assert_eq!(forwarded_to(&snap, "hello@example.com"), ["me@x.test"]);
    assert_eq!(
        forwarded_to(&snap, "billing@example.com"),
        ["finance@x.test"]
    );
}

#[test]
fn an_alias_that_inherits_nothing_blocks_publication() {
    let d = domain("example.com", vec![inheriting("hello")]);
    match Snapshot::build(vec![d]) {
        Err(BuildError::InheritsNothing { pattern, .. }) => assert_eq!(pattern, "hello"),
        other => panic!("published an alias that resolves nowhere: {other:?}"),
    }
}

#[test]
fn a_catch_all_that_inherits_nothing_blocks_publication() {
    let mut d = domain("example.com", vec![]);
    d.catchall = Some(CatchAllInput { destination: None });
    match Snapshot::build(vec![d]) {
        Err(BuildError::CatchAllInheritsNothing { .. }) => {}
        other => panic!("published a catch-all that routes nowhere: {other:?}"),
    }
}

// ------------------------------------------------------------ §7 validation

#[test]
fn a_reject_rule_with_destinations_blocks_publication() {
    // SQLite cannot express this: a CHECK cannot reach another table.
    let d = domain(
        "example.com",
        vec![AliasInput {
            pattern: "hello".into(),
            reject: true,
            destinations: vec![dest("me@x.test")],
        }],
    );
    match Snapshot::build(vec![d]) {
        Err(BuildError::RejectWithDestinations { .. }) => {}
        other => panic!("published a rule that both refuses and forwards: {other:?}"),
    }
}

#[test]
fn a_malformed_exact_alias_blocks_publication() {
    for bad in ["hello world", "a@b", "", "hello\u{7f}"] {
        let d = domain("example.com", vec![alias(bad, &["me@x.test"])]);
        assert!(
            Snapshot::build(vec![d]).is_err(),
            "published an alias no address could ever match: {bad:?}"
        );
    }
}

#[test]
fn a_malformed_managed_domain_blocks_publication() {
    for bad in [
        "example",
        "exa mple.com",
        "-example.com",
        "example..com",
        "",
    ] {
        let d = domain(bad, vec![alias("hello", &["me@x.test"])]);
        match Snapshot::build(vec![d]) {
            Err(BuildError::DomainNotAnALabel { .. }) => {}
            other => panic!("published an unmatchable domain {bad:?}: {other:?}"),
        }
    }
}

#[test]
fn more_than_one_star_blocks_publication() {
    let d = domain("example.com", vec![alias("a*b*c", &["me@x.test"])]);
    match Snapshot::build(vec![d]) {
        Err(BuildError::BadPattern { .. }) => {}
        other => panic!("published a two-star pattern: {other:?}"),
    }
}

#[test]
fn ambiguous_equal_precedence_wildcards_block_publication() {
    // `a*c` and `ab*` both match `abc` and both carry two literals. A
    // deterministic tie-break would make that repeatable rather than correct:
    // one of the two rules never applies and nothing says so.
    let d = domain(
        "example.com",
        vec![alias("a*c", &["one@x.test"]), alias("ab*", &["two@x.test"])],
    );
    match Snapshot::build(vec![d]) {
        Err(BuildError::AmbiguousWildcards { .. }) => {}
        other => panic!("published an ambiguous configuration: {other:?}"),
    }
}

#[test]
fn equal_precedence_wildcards_that_agree_are_only_reported() {
    let d = domain(
        "example.com",
        vec![
            alias("a*c", &["same@x.test"]),
            alias("ab*", &["same@x.test"]),
        ],
    );
    let built = Snapshot::build(vec![d]).expect("identical outcomes are not ambiguous");
    assert!(
        built
            .reports
            .iter()
            .any(|r| matches!(r, Report::RedundantWildcards { .. })),
        "{:?}",
        built.reports
    );
}

#[test]
fn non_overlapping_wildcards_of_equal_precedence_are_fine() {
    // Equal precedence alone is not ambiguity — they have to be able to match
    // the same address.
    let d = domain(
        "example.com",
        vec![alias("ab*", &["one@x.test"]), alias("cd*", &["two@x.test"])],
    );
    let built = Snapshot::build(vec![d]).expect("disjoint patterns are not ambiguous");
    assert!(built.reports.is_empty(), "{:?}", built.reports);
}

#[test]
fn a_redundant_alias_is_reported_and_not_refused() {
    let mut d = domain("example.com", vec![alias("hello", &["me@x.test"])]);
    d.catchall = Some(CatchAllInput {
        destination: Some(vec![dest("me@x.test")]),
    });
    let built = Snapshot::build(vec![d]).expect("redundancy is not an error");
    assert!(
        built
            .reports
            .iter()
            .any(|r| matches!(r, Report::RedundantAgainstCatchAll { .. })),
        "{:?}",
        built.reports
    );
}

// ----------------------------------------------------------------- §6 loops

#[test]
fn a_self_referential_alias_blocks_publication() {
    let d = domain("example.com", vec![alias("abuse", &["abuse@example.com"])]);
    match Snapshot::build(vec![d]) {
        Err(BuildError::Loop { .. }) => {}
        other => panic!("published an alias that forwards to itself: {other:?}"),
    }
}

#[test]
fn an_indirect_cycle_across_domains_blocks_publication() {
    // Depth two. A detector that only compares a destination against its own
    // origin passes this.
    let one = domain("one.test", vec![alias("a", &["b@two.test"])]);
    let two = domain("two.test", vec![alias("b", &["a@one.test"])]);
    match Snapshot::build(vec![one, two]) {
        Err(BuildError::Loop { .. }) => {}
        other => panic!("published a two-hop cycle: {other:?}"),
    }
}

#[test]
fn a_cycle_through_wildcards_blocks_publication() {
    // Destinations are concrete, so a wildcard is only ever asked whether it
    // matches a concrete address — which it answers exactly, with no pattern
    // intersection anywhere.
    let x = domain("x.test", vec![alias("a-*", &["a-1@y.test"])]);
    let y = domain("y.test", vec![alias("a-*", &["a-1@x.test"])]);
    match Snapshot::build(vec![x, y]) {
        Err(BuildError::Loop { .. }) => {}
        other => panic!("published a cycle through wildcards: {other:?}"),
    }
}

#[test]
fn a_valid_diamond_is_not_a_loop() {
    // `a` fans out to `b` and `c`, both of which forward to `d`. `d` is reached
    // twice by different routes and there is no cycle anywhere.
    //
    // A single global visited set reports the second arrival as a loop and
    // refuses a perfectly valid configuration. Fanning one alias out to several
    // destinations is advertised, so diamonds are ordinary.
    let d = DomainInput {
        name: "example.com".into(),
        gate: live(),
        plus_addressing: true,
        default_destination: None,
        aliases: vec![
            alias("a", &["b@example.com", "c@example.com"]),
            alias("b", &["d@example.com"]),
            alias("c", &["d@example.com"]),
            alias("d", &["out@elsewhere.test"]),
        ],
        catchall: None,
    };
    let snap = build(vec![d]);
    assert_eq!(forwarded_to(&snap, "d@example.com"), ["out@elsewhere.test"]);
}

#[test]
fn a_deep_but_acyclic_chain_is_not_a_loop() {
    // A fixed hop limit refuses this, which is a bug that looks like a policy.
    let mut aliases = Vec::new();
    for i in 0..64 {
        aliases.push(alias(
            &format!("a{i}"),
            &[&format!("a{}@example.com", i + 1)],
        ));
    }
    aliases.push(alias("a64", &["out@elsewhere.test"]));

    let d = DomainInput {
        name: "example.com".into(),
        gate: live(),
        plus_addressing: true,
        default_destination: None,
        aliases,
        catchall: None,
    };
    let snap = build(vec![d]);
    assert_eq!(
        forwarded_to(&snap, "a64@example.com"),
        ["out@elsewhere.test"]
    );
}

#[test]
fn a_loop_through_a_disabled_domain_still_blocks_publication() {
    // A loop through a gated domain is still a loop, and it starts looping the
    // moment the domain returns — when nobody is looking for a configuration
    // change, because there was not one.
    let one = domain("one.test", vec![alias("a", &["b@two.test"])]);
    let mut two = domain("two.test", vec![alias("b", &["a@one.test"])]);
    two.gate.inbound_enabled = false;
    two.gate.status = DomainStatus::Error;

    match Snapshot::build(vec![one, two]) {
        Err(BuildError::Loop { .. }) => {}
        other => panic!("a loop was hidden by a disabled domain: {other:?}"),
    }
}

#[test]
fn forwarding_out_of_the_managed_set_is_not_a_loop() {
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello", &["me@gmail.test"])],
    )]);
    assert_eq!(forwarded_to(&snap, "hello@example.com"), ["me@gmail.test"]);
}

// ------------------------------------------------------------------ gating

#[test]
fn a_domain_that_is_not_accepting_resolves_nothing() {
    for (status, enabled) in [
        (DomainStatus::Error, true),
        (DomainStatus::Active, false),
        (DomainStatus::PendingDns, true),
    ] {
        let mut d = domain("example.com", vec![alias("hello", &["me@x.test"])]);
        d.gate.status = status;
        d.gate.inbound_enabled = enabled;
        let snap = build(vec![d]);

        let a = addr("hello@example.com");
        assert!(
            matches!(route(&snap, &a), Decision::DomainNotAccepting),
            "{status:?}/{enabled} accepted mail"
        );
    }
}

#[test]
fn an_unmanaged_domain_is_distinguishable_from_an_unrouted_address() {
    // Different answers because they need different diagnostics, and because
    // one of them is how open-relay refusal reads at RCPT TO.
    let snap = build(vec![domain(
        "example.com",
        vec![alias("hello", &["me@x.test"])],
    )]);

    let unknown = addr("anyone@elsewhere.test");
    assert!(matches!(route(&snap, &unknown), Decision::UnknownDomain));

    let unrouted = addr("nobody@example.com");
    assert!(matches!(route(&snap, &unrouted), Decision::NoRoute));
}

// ------------------------------------------------------------- determinism

#[test]
fn resolving_the_same_address_twice_gives_the_same_answer() {
    let mut d = domain(
        "example.com",
        vec![
            alias("shop-*", &["shop@x.test"]),
            alias("shop-old-*", &["old@x.test"]),
            alias("hello", &["me@x.test"]),
        ],
    );
    d.catchall = Some(CatchAllInput {
        destination: Some(vec![dest("all@x.test")]),
    });
    let snap = build(vec![d]);

    for address in [
        "hello@example.com",
        "shop-1@example.com",
        "shop-old-2@example.com",
        "whatever@example.com",
        "hello+tag@example.com",
    ] {
        let first = forwarded_to(&snap, address);
        for _ in 0..8 {
            assert_eq!(forwarded_to(&snap, address), first, "{address}");
        }
    }
}
