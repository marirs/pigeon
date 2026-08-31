//! Checks that need a real resolver, and are therefore ignored by default.
//!
//! `cargo test -p pigeon-auth --test live_dns -- --ignored`
//!
//! CI does not run these: a test that fails when a network is unavailable
//! teaches people to ignore failures. They exist because two of M2's decisions
//! rest on runtime behaviour that no amount of reading establishes —
//! `M2-DESIGN.md` §8, measurements 3 and 4.

use std::net::IpAddr;

use pigeon_auth::verify::{DmarcPolicy, Envelope, Outcome, Received, Verifier};

fn verifier() -> Verifier {
    Verifier::from_system().expect("no system resolver")
}

/// A message from a domain that publishes DMARC `p=reject`, DKIM and SPF.
fn message(from_domain: &str) -> Vec<u8> {
    format!(
        "From: <postmaster@{from_domain}>\r\n\
         To: <someone@example.com>\r\n\
         Subject: live check\r\n\
         \r\n\
         body\r\n"
    )
    .into_bytes()
}

#[tokio::test]
#[ignore = "needs DNS"]
async fn dmarc_is_evaluated_without_the_report_feature() {
    // Measurement 4. `report` was dropped to keep `zip` and `quick-xml` out of
    // the graph, and compiling proves nothing about whether the evaluation path
    // survived: `report` gates report *generation*, and if it had also gated
    // policy lookup this would return Unspecified for a domain that publishes
    // one of the most-published DMARC records in existence.
    let raw = message("google.com");
    let verdicts = verifier()
        .verify(
            Received::new(&raw),
            &Envelope {
                client_ip: "192.0.2.1".parse::<IpAddr>().unwrap(),
                helo: "mail.google.com",
                mail_from: "postmaster@google.com",
                host_domain: "pigeon.test",
            },
        )
        .await;

    assert_ne!(
        verdicts.dmarc.policy,
        DmarcPolicy::Unspecified,
        "no DMARC policy was read for google.com; the evaluation path is gated \
         behind the `report` feature after all"
    );
    assert_eq!(verdicts.dmarc.domain, "google.com");

    // And the record was actually applied: an unauthorised IP under a domain
    // that publishes SPF must not come back as an aligned pass.
    assert!(
        !verdicts.dmarc.passes(),
        "192.0.2.1 authenticated as google.com"
    );
}

#[tokio::test]
#[ignore = "needs DNS"]
async fn a_domain_that_publishes_nothing_is_none_not_temperror() {
    // The distinction the whole classification exists for, on the mail-auth
    // side: "no record" is a permanent fact about the domain, and "the
    // resolver could not answer" is a fact about the network. Reporting the
    // first as the second makes every unauthenticated message look like an
    // outage.
    let raw = message("example.com");
    let verdicts = verifier()
        .verify(
            Received::new(&raw),
            &Envelope {
                client_ip: "192.0.2.1".parse::<IpAddr>().unwrap(),
                helo: "example.com",
                mail_from: "postmaster@example.com",
                host_domain: "pigeon.test",
            },
        )
        .await;

    assert_ne!(
        verdicts.spf,
        Outcome::TempError,
        "a domain with no SPF record was reported as a resolver failure"
    );
    assert!(
        verdicts.dkim.is_empty(),
        "an unsigned message produced DKIM verdicts"
    );
    assert!(!verdicts.authentication_results.is_empty());
}
