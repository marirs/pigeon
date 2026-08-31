//! A DNS cache that answers with exactly the records a test publishes.
//!
//! Signing and sealing are only interesting if somebody can check the result,
//! and checking needs the public key in DNS — which a test cannot publish.
//! `mail-auth` consults a cache before the resolver, so a hit means no query
//! and the verification result depends only on the bytes under test.
//!
//! Deliberately not backed by the real resolver in any way. A fixture that can
//! fall through to the network passes for the wrong reason on the one machine
//! where the real record happens to exist.

use std::borrow::Borrow;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use mail_auth::{
    MX, RecordSet, ResolverCache, Txt, common::parse::TxtRecordParser, common::verify::DomainKey,
};

/// Serves one DKIM public key to whoever asks.
#[derive(Default)]
pub struct DnsStub(Mutex<Option<Txt>>);

impl DnsStub {
    /// Publish a DKIM record — `v=DKIM1; k=rsa; p=...` — for the whole stub.
    ///
    /// The lookup key is not inspected. `mail-auth` asks for exactly one name
    /// in this situation, `<selector>._domainkey.<domain>`, and a stub that
    /// matched on the name would be asserting the lookup key rather than the
    /// signature. What a test asserts is the verification *result*, which is a
    /// pass only if the key served here is the one that signed the bytes.
    pub fn with_dkim_record(record: &str) -> Self {
        let stub = Self::default();
        *stub.0.lock().unwrap() = Some(Txt::DomainKey(Arc::new(
            DomainKey::parse(record.as_bytes()).expect("the fixture record does not parse"),
        )));
        stub
    }
}

impl ResolverCache<Box<str>, Txt> for DnsStub {
    fn get<Q>(&self, _name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().unwrap().clone()
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

/// The other four caches, which nothing here populates.
///
/// Present because `Parameters` is generic over all five and `None` still needs
/// a type. An empty cache means the resolver *would* be consulted, so a test
/// that depends on an MX, PTR or address lookup is one that reaches the
/// network — which is exactly what these are not for.
macro_rules! empty_cache {
    ($key:ty, $value:ty) => {
        impl ResolverCache<$key, $value> for DnsStub {
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

empty_cache!(Box<str>, RecordSet<MX>);
empty_cache!(Box<str>, RecordSet<std::net::Ipv4Addr>);
empty_cache!(Box<str>, RecordSet<std::net::Ipv6Addr>);
empty_cache!(IpAddr, RecordSet<Box<str>>);
