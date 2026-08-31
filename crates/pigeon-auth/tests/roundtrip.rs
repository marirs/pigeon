//! Verifying Pigeon's own output, offline.
//!
//! Signing and sealing are only interesting if somebody can check the result,
//! and checking it needs the public key in DNS — which a test cannot publish.
//! `mail-auth` takes an optional cache for every lookup it makes, so the stub
//! below answers the one query that matters and no packet leaves the machine.
//!
//! This is what closes the two properties a mutation run showed were
//! unfalsifiable: that the ARC set covers the message **as sent** rather than
//! as received, and that a chain arriving `cv=fail` is not extended. Both are
//! invisible to any assertion about header order — the bytes differ only in
//! what was hashed.

use std::borrow::Borrow;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use mail_auth::{
    AuthenticatedMessage, DkimResult, MessageAuthenticator, Parameters, ResolverCache, Txt,
    common::parse::TxtRecordParser, common::verify::DomainKey,
};
use pigeon_auth::{
    dkim::KeyPair,
    pipeline::{Pipeline, Rewrite, SigningKey},
    verify::{Envelope, Verifier},
};

// ------------------------------------------------------------------- the stub

/// A TXT cache holding exactly the records a test publishes.
///
/// `mail-auth` checks the cache before the resolver, so a hit means no query.
/// Deliberately not backed by the real resolver in any way: a fixture that can
/// fall through to the network passes for the wrong reason on the one machine
/// where the real record happens to exist.
#[derive(Default)]
struct TxtStub(Mutex<Vec<(String, Txt)>>);

impl TxtStub {
    fn with_key(name: &str, record: &str) -> Self {
        let stub = Self::default();
        stub.0.lock().unwrap().push((
            name.to_string(),
            Txt::DomainKey(std::sync::Arc::new(
                DomainKey::parse(record.as_bytes()).expect("the fixture record does not parse"),
            )),
        ));
        stub
    }
}

impl ResolverCache<Box<str>, Txt> for TxtStub {
    /// Answers with the single record this stub was built with.
    ///
    /// The key is not inspected. `mail-auth` asks for exactly one name in these
    /// tests — `<selector>._domainkey.<domain>` for the signature being checked
    /// — and a stub that matched on the name would be asserting the lookup key
    /// rather than the signature. What each test actually asserts is the
    /// verification *result*, which is `Pass` only if the key served here is
    /// the one that signed the bytes under test.
    fn get<Q>(&self, _name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().unwrap().first().map(|(_, v)| v.clone())
    }

    fn remove<Q>(&self, _name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        None
    }

    fn insert(&self, _key: Box<str>, _value: Txt, _valid_until: Instant) {}
}

/// The other four caches, which these tests never populate.
///
/// Present because `Parameters` is generic over all five and `None` still needs
/// a type. An empty cache means the resolver would be consulted — which is why
/// no test here depends on an MX, PTR or address lookup.
macro_rules! empty_cache {
    ($key:ty, $value:ty) => {
        impl ResolverCache<$key, $value> for TxtStub {
            fn get<Q>(&self, _name: &Q) -> Option<$value>
            where
                $key: Borrow<Q>,
                Q: Hash + Eq + ?Sized,
            {
                None
            }

            fn remove<Q>(&self, _name: &Q) -> Option<$value>
            where
                $key: Borrow<Q>,
                Q: Hash + Eq + ?Sized,
            {
                None
            }

            fn insert(&self, _key: $key, _value: $value, _valid_until: Instant) {}
        }
    };
}

empty_cache!(Box<str>, mail_auth::RecordSet<mail_auth::MX>);
empty_cache!(Box<str>, mail_auth::RecordSet<std::net::Ipv4Addr>);
empty_cache!(Box<str>, mail_auth::RecordSet<std::net::Ipv6Addr>);
empty_cache!(IpAddr, mail_auth::RecordSet<Box<str>>);

// ------------------------------------------------------------------ fixtures

const SELECTOR: &str = "sel";
const DOMAIN: &str = "pigeon.test";

fn envelope() -> Envelope<'static> {
    Envelope {
        client_ip: "192.0.2.10".parse::<IpAddr>().unwrap(),
        helo: "sender.example",
        mail_from: "alice@sender.example",
        host_domain: DOMAIN,
    }
}

const MESSAGE: &[u8] =
    b"From: <alice@sender.example>\r\nTo: <bob@example.com>\r\nSubject: hi\r\n\r\nbody\r\n";

const RECEIVED: &str = "Received: from sender.example by pigeon.test; today";

#[tokio::test]
async fn pigeons_own_signature_verifies_against_the_message_it_sent() {
    // The property no header-order assertion can reach: the signature is over
    // the bytes that leave, including the headers added above the original
    // message. Signing the received form instead produces a header that looks
    // identical and does not verify.
    let pair = KeyPair::generate(2048).unwrap();
    let stub = TxtStub::with_key(
        &pigeon_auth::dkim::record_name(SELECTOR, DOMAIN),
        &pair.txt_record(),
    );

    let pipeline = Pipeline::new(Verifier::from_system().unwrap(), DOMAIN).with_signing_key(
        SigningKey::from_pkcs8_pem(pair.private_pem(), DOMAIN, SELECTOR).unwrap(),
    );

    let out = pipeline
        .process(
            MESSAGE,
            &envelope(),
            RECEIVED,
            &Rewrite::From {
                header: format!("From: <forward@{DOMAIN}>"),
            },
        )
        .await
        .unwrap();
    assert!(out.signed && out.sealed, "{out:?}");

    // Verified with the stub answering the key lookup, so nothing leaves the
    // machine and the result depends only on the bytes.
    let authenticator = MessageAuthenticator::new_system_conf().unwrap();
    let parsed = AuthenticatedMessage::parse(out.payload.as_bytes()).unwrap();
    let results = authenticator
        .verify_dkim(Parameters {
            params: &parsed,
            cache_txt: Some(&stub),
            cache_mx: None::<&TxtStub>,
            cache_ptr: None::<&TxtStub>,
            cache_ipv4: None::<&TxtStub>,
            cache_ipv6: None::<&TxtStub>,
        })
        .await;

    let ours = results
        .iter()
        .find(|r| r.signature().is_some_and(|s| s.d == DOMAIN))
        .expect("Pigeon's own signature is missing from the relayed message");
    assert_eq!(
        ours.result(),
        &DkimResult::Pass,
        "Pigeon's signature does not verify against the message it sent: {:?}",
        ours.result()
    );
}

#[tokio::test]
async fn the_arc_set_verifies_against_the_message_it_sent() {
    // The seal's half of the same property, and the one that needed this
    // harness most: the ARC-Message-Signature covers the outbound form —
    // the Received header, the Authentication-Results and Pigeon's own DKIM
    // signature included. Sealing over the received bytes instead produces a
    // set that looks identical in the header order and does not validate.
    let pair = KeyPair::generate(2048).unwrap();
    let stub = TxtStub::with_key(
        &pigeon_auth::dkim::record_name(SELECTOR, DOMAIN),
        &pair.txt_record(),
    );

    let pipeline = Pipeline::new(Verifier::from_system().unwrap(), DOMAIN).with_signing_key(
        SigningKey::from_pkcs8_pem(pair.private_pem(), DOMAIN, SELECTOR).unwrap(),
    );

    let out = pipeline
        .process(
            MESSAGE,
            &envelope(),
            RECEIVED,
            &Rewrite::From {
                header: format!("From: <forward@{DOMAIN}>"),
            },
        )
        .await
        .unwrap();
    assert!(out.sealed, "{out:?}");

    let authenticator = MessageAuthenticator::new_system_conf().unwrap();
    let parsed = AuthenticatedMessage::parse(out.payload.as_bytes()).unwrap();
    let arc = authenticator
        .verify_arc(Parameters {
            params: &parsed,
            cache_txt: Some(&stub),
            cache_mx: None::<&TxtStub>,
            cache_ptr: None::<&TxtStub>,
            cache_ipv4: None::<&TxtStub>,
            cache_ipv6: None::<&TxtStub>,
        })
        .await;

    assert_eq!(
        arc.result(),
        &DkimResult::Pass,
        "the ARC set does not validate against the message Pigeon sent: {:?}",
        arc.result()
    );
}

#[tokio::test]
async fn a_chain_that_arrived_failed_is_not_extended() {
    // RFC 8617: a chain whose most recent set declares cv=fail is terminally
    // broken, and appending to it produces a longer broken chain and nothing
    // else. Distinct from Pigeon *finding* a chain invalid, where the failure
    // set is the one useful thing it can record.
    let pair = KeyPair::generate(2048).unwrap();
    let stub = TxtStub::with_key(
        &pigeon_auth::dkim::record_name(SELECTOR, DOMAIN),
        &pair.txt_record(),
    );
    let _ = &stub;

    let dead_chain = format!(
        "ARC-Seal: i=1; a=rsa-sha256; cv=fail; d={DOMAIN}; s={SELECTOR}; b=AAAA\r\n\
         ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d={DOMAIN}; s={SELECTOR}; \
         h=from; bh=AAAA; b=AAAA\r\n\
         ARC-Authentication-Results: i=1; {DOMAIN}; dkim=fail\r\n\
         From: <alice@sender.example>\r\nSubject: hi\r\n\r\nbody\r\n"
    );

    let pipeline = Pipeline::new(Verifier::from_system().unwrap(), DOMAIN).with_signing_key(
        SigningKey::from_pkcs8_pem(pair.private_pem(), DOMAIN, SELECTOR).unwrap(),
    );

    let out = pipeline
        .process(
            dead_chain.as_bytes(),
            &envelope(),
            RECEIVED,
            &Rewrite::Preserve,
        )
        .await
        .unwrap();

    assert!(!out.sealed, "a dead chain was extended");
    assert_eq!(
        out.seal_skipped,
        Some(pigeon_auth::pipeline::SealSkipped::ChainAlreadyFailed)
    );
    // And the message is still forwarded, with the original chain intact.
    let text = String::from_utf8(out.payload.as_bytes().to_vec()).unwrap();
    assert!(
        text.contains("ARC-Seal: i=1"),
        "the inbound chain was altered"
    );
    assert_eq!(
        text.matches("ARC-Seal:").count(),
        1,
        "a second set was added"
    );
}
