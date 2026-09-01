//! What the routing fingerprint notices.
//!
//! Every field it covers is one a restore can change at the same revision
//! (`M1-RELOAD.md` C-2). Anything it does not notice is a configuration that
//! can be swapped underneath a running daemon in silence — and once `RCPT`
//! resolves against the snapshot, that is misdelivered mail rather than stale
//! metadata.

use pigeon_route::reload::fingerprint;
use pigeon_route::snapshot::{
    AliasInput, CatchAllInput, Destination, DkimIdentity, DomainInput, Forwarding,
};
use pigeon_types::{DomainGate, DomainStatus, ForwardPolicy};

fn destination(local: &str, domain: &str) -> Destination {
    Destination {
        local: local.into(),
        domain: domain.into(),
    }
}

fn domain() -> DomainInput {
    DomainInput {
        name: "example.com".into(),
        gate: DomainGate {
            status: DomainStatus::Active,
            inbound_enabled: true,
            outbound_enabled: false,
        },
        plus_addressing: true,
        forwarding: Forwarding {
            policy: ForwardPolicy::Preserve,
            dkim: Some(DkimIdentity {
                selector: "sel".into(),
                private_key_path: "example.com/sel.key".into(),
                algorithm: "rsa2048".into(),
            }),
        },
        default_destination: Some(destination("me", "example.net")),
        aliases: vec![AliasInput {
            pattern: "hello".into(),
            reject: false,
            destinations: vec![destination("hello", "example.net")],
        }],
        catchall: Some(CatchAllInput {
            destination: Some(vec![destination("catch", "example.net")]),
        }),
    }
}

/// Assert that a change to the configuration changes the fingerprint.
fn notices(what: &str, edit: impl Fn(&mut DomainInput)) {
    let base = vec![domain()];
    let mut changed = vec![domain()];
    edit(&mut changed[0]);
    assert_ne!(
        fingerprint(&base),
        fingerprint(&changed),
        "the fingerprint does not notice {what}"
    );
}

#[test]
fn the_same_configuration_hashes_the_same() {
    assert_eq!(fingerprint(&[domain()]), fingerprint(&[domain()]));
}

#[test]
fn it_notices_every_runtime_input() {
    notices("a renamed domain", |d| d.name = "other.example".into());
    notices("a gate status", |d| d.gate.status = DomainStatus::New);
    notices("inbound being switched off", |d| {
        d.gate.inbound_enabled = false
    });
    notices("outbound being switched on", |d| {
        d.gate.outbound_enabled = true
    });
    notices("plus addressing", |d| d.plus_addressing = false);

    // The policy decides what is signed and under whose identity, so a restore
    // that flips it changes every forwarded message.
    notices("the forwarding policy", |d| {
        d.forwarding.policy = ForwardPolicy::RewriteFrom
    });

    notices("a new selector", |d| {
        d.forwarding.dkim.as_mut().unwrap().selector = "other".into()
    });
    notices("a different key algorithm", |d| {
        d.forwarding.dkim.as_mut().unwrap().algorithm = "ed25519".into()
    });
    // Two domains pointing at different files is a different runtime even when
    // the selectors match.
    notices("a different key file", |d| {
        d.forwarding.dkim.as_mut().unwrap().private_key_path = "example.com/other.key".into()
    });
    notices("a key being removed", |d| d.forwarding.dkim = None);

    notices("a changed default destination", |d| {
        d.default_destination = Some(destination("someone-else", "example.net"))
    });
    notices("a removed default destination", |d| {
        d.default_destination = None
    });

    notices("a changed alias pattern", |d| {
        d.aliases[0].pattern = "goodbye".into()
    });
    // A reject rule and a forward rule are different answers to one address.
    notices("an alias becoming a reject", |d| d.aliases[0].reject = true);
    notices("a changed alias destination", |d| {
        d.aliases[0].destinations = vec![destination("elsewhere", "example.net")]
    });
    notices("an added alias destination", |d| {
        d.aliases[0]
            .destinations
            .push(destination("second", "example.net"))
    });
    notices("a removed alias", |d| d.aliases.clear());

    notices("a changed catch-all", |d| {
        d.catchall = Some(CatchAllInput {
            destination: Some(vec![destination("elsewhere", "example.net")]),
        })
    });
    notices("a catch-all becoming inherited", |d| {
        d.catchall = Some(CatchAllInput { destination: None })
    });
    notices("a removed catch-all", |d| d.catchall = None);
}

#[test]
fn it_notices_a_changed_local_part_but_folds_nothing() {
    // `Bob@x` and `bob@x` are different mailboxes: the local part belongs to
    // the destination host, and a restore that changes one is a change.
    notices("a recased local part", |d| {
        d.default_destination = Some(destination("Me", "example.net"))
    });
}

#[test]
fn order_is_not_a_change() {
    // The comparison answers "is this the same routing", not "did the rows
    // arrive in the same order" — otherwise every reconciliation would report a
    // divergence the moment a query plan changed.
    let mut a = domain();
    a.aliases = vec![
        AliasInput {
            pattern: "one".into(),
            reject: false,
            destinations: vec![
                destination("a", "example.net"),
                destination("b", "example.net"),
            ],
        },
        AliasInput {
            pattern: "two".into(),
            reject: false,
            destinations: vec![],
        },
    ];

    let mut b = domain();
    b.aliases = vec![
        AliasInput {
            pattern: "two".into(),
            reject: false,
            destinations: vec![],
        },
        AliasInput {
            pattern: "one".into(),
            reject: false,
            destinations: vec![
                destination("b", "example.net"),
                destination("a", "example.net"),
            ],
        },
    ];

    assert_eq!(fingerprint(&[a]), fingerprint(&[b]));

    // And the same for domains.
    let mut x = domain();
    x.name = "a.example".into();
    let mut y = domain();
    y.name = "b.example".into();
    assert_eq!(
        fingerprint(&[x.clone(), y.clone()]),
        fingerprint(&[y, x]),
        "domain order changed the fingerprint"
    );
}

#[test]
fn fields_cannot_be_confused_with_one_another() {
    // The reason for length delimiters, shown on two fields that are adjacent
    // in the encoding and both free-form: the DKIM selector and the algorithm.
    // Written with a separator — or with none — these two configurations
    // produce the same bytes and therefore the same hash, and a routing
    // fingerprint that collides is a restore reconciliation cannot detect.
    let mut a = domain();
    let k = a.forwarding.dkim.as_mut().unwrap();
    k.selector = "sel".into();
    k.algorithm = "rsa2048".into();

    let mut b = domain();
    let k = b.forwarding.dkim.as_mut().unwrap();
    k.selector = "selrsa".into();
    k.algorithm = "2048".into();

    assert_ne!(
        fingerprint(&[a]),
        fingerprint(&[b]),
        "two configurations differing only in where a field boundary falls hash the same"
    );
}
