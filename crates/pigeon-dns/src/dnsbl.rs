//! DNS blocklist lookups.
//!
//! A blocklist is asked "is this address listed?" by looking up the address
//! reversed under the list's zone: `192.0.2.10` on `zen.spamhaus.org` becomes
//! `10.2.0.192.zen.spamhaus.org`. An `A` record means listed; `NXDOMAIN` means
//! not.
//!
//! # Fail open, always
//!
//! A blocklist that cannot be reached says **nothing**, and a resolver failure
//! must never become a rejection. The reason is asymmetric, as it is everywhere
//! else in this project: a list that is down and is treated as "listed" refuses
//! every message from everyone, which is a total mail outage produced by
//! somebody else's DNS server. Treating the same failure as "not listed"
//! forwards spam that would otherwise have been refused — recoverable, and
//! visible.
//!
//! This is also why the answer is a three-way one. "Not listed" and "could not
//! tell" are different facts, and a caller that wants to log the difference —
//! or to escalate when every list is unreachable — needs to see it.
//!
//! # Why the address is reversed
//!
//! Because DNS delegates from the right. Reversing the octets puts the most
//! significant part of the address at the *end* of the name, so one zone can
//! answer for every address without the list operator delegating a subtree per
//! octet.

use std::future::Future;
use std::net::IpAddr;

use crate::resolver::{LookupError, SystemResolver};

/// What a blocklist said about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// Listed, with the codes returned. The codes are the list's own encoding
    /// of *why*, and are kept because "listed by zen.spamhaus.org as
    /// 127.0.0.4" is what an operator needs to look up when a sender complains.
    Listed { zone: String, codes: Vec<IpAddr> },
    /// Not listed by any zone consulted.
    NotListed,
    /// No zone could answer. Never a rejection: see the module docs.
    Unknown { reason: String },
}

/// Build the query name for an address under a zone.
///
/// IPv6 is nibble-reversed rather than octet-reversed, which is the same idea
/// at a finer grain — the delegation still runs from the right, and a list that
/// answers for IPv6 publishes it that way.
pub fn query_name(address: IpAddr, zone: &str) -> String {
    let zone = zone.trim_end_matches('.');
    match address {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(64 + zone.len());
            for octet in v6.octets().iter().rev() {
                // Low nibble first, then high: the whole address reversed at
                // nibble granularity.
                name.push_str(&format!("{:x}.{:x}.", octet & 0x0f, octet >> 4));
            }
            name.push_str(zone);
            name
        }
    }
}

/// What a blocklist lookup can answer.
///
/// A trait so the decision can be tested without a live list: the rules here —
/// first listing wins, one "not listed" is an answer, no answers at all is
/// `Unknown` — are the part worth proving, and none of them is about DNS.
pub trait Blocklist: Send + Sync {
    fn listed(&self, name: &str) -> impl Future<Output = Result<Vec<IpAddr>, LookupError>> + Send;
}

impl Blocklist for SystemResolver {
    async fn listed(&self, name: &str) -> Result<Vec<IpAddr>, LookupError> {
        self.lookup_a(name).await
    }
}

/// Whether an address is listed by any of `zones`.
///
/// Zones are consulted in order and the first listing wins: one answer is
/// enough to refuse, and asking the rest costs a round trip to learn nothing
/// that changes the outcome.
pub async fn check<B: Blocklist>(resolver: &B, address: IpAddr, zones: &[String]) -> Listing {
    if zones.is_empty() {
        return Listing::NotListed;
    }

    // Remembered rather than returned immediately: a zone that fails must not
    // stop the others being asked, and "every zone failed" is only knowable at
    // the end.
    let mut failure: Option<String> = None;
    let mut answered = false;

    for zone in zones {
        match resolver.listed(&query_name(address, zone)).await {
            Ok(codes) if !codes.is_empty() => {
                return Listing::Listed {
                    zone: zone.clone(),
                    codes,
                };
            }
            // Present but empty, or absent: both mean not listed by this zone.
            Ok(_) | Err(LookupError::NoSuchDomain(_)) | Err(LookupError::NoRecords(_)) => {
                answered = true;
            }
            Err(e) => {
                tracing::warn!(%zone, %address, error = %e, "a blocklist could not be consulted");
                failure = Some(format!("{zone}: {e}"));
            }
        }
    }

    // One zone answering "not listed" is an answer. `Unknown` is reserved for
    // having learned nothing at all, because a caller that escalates on it
    // should not be escalating because the third list of four was slow.
    match (answered, failure) {
        (true, _) => Listing::NotListed,
        (false, Some(reason)) => Listing::Unknown { reason },
        (false, None) => Listing::NotListed,
    }
}

/// A list with fixed answers, for tests.
#[derive(Default)]
pub struct FakeBlocklist {
    listed: std::collections::HashMap<String, Vec<IpAddr>>,
    failing: bool,
}

impl FakeBlocklist {
    pub fn new() -> Self {
        Self::default()
    }

    /// List `address` under `zone`, returning `codes`.
    pub fn listing(mut self, address: IpAddr, zone: &str, codes: Vec<IpAddr>) -> Self {
        self.listed.insert(query_name(address, zone), codes);
        self
    }

    /// Answer nothing at all, as an unreachable list does.
    pub fn unreachable(mut self) -> Self {
        self.failing = true;
        self
    }
}

impl Blocklist for FakeBlocklist {
    async fn listed(&self, name: &str) -> Result<Vec<IpAddr>, LookupError> {
        if self.failing {
            return Err(LookupError::Resolver("no answer".into()));
        }
        match self.listed.get(name) {
            Some(codes) => Ok(codes.clone()),
            None => Err(LookupError::NoSuchDomain(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }

    #[tokio::test]
    async fn a_listing_names_the_zone_and_keeps_the_codes() {
        // The codes are the list's encoding of *why*, and "listed by zen as
        // 127.0.0.4" is what an operator needs when a sender complains.
        let list = FakeBlocklist::new().listing(
            client(),
            "zen.example",
            vec!["127.0.0.4".parse().unwrap()],
        );

        assert_eq!(
            check(&list, client(), &["zen.example".to_string()]).await,
            Listing::Listed {
                zone: "zen.example".into(),
                codes: vec!["127.0.0.4".parse().unwrap()]
            }
        );
    }

    #[tokio::test]
    async fn an_unlisted_address_passes_every_zone() {
        let list = FakeBlocklist::new();
        assert_eq!(
            check(
                &list,
                client(),
                &["one.example".to_string(), "two.example".to_string()]
            )
            .await,
            Listing::NotListed
        );
    }

    #[tokio::test]
    async fn a_later_zone_still_lists() {
        // Zones are consulted in order, and a list that answers second is as
        // good as one that answers first.
        let list = FakeBlocklist::new().listing(
            client(),
            "two.example",
            vec!["127.0.0.2".parse().unwrap()],
        );
        assert!(matches!(
            check(
                &list,
                client(),
                &["one.example".to_string(), "two.example".to_string()]
            )
            .await,
            Listing::Listed { zone, .. } if zone == "two.example"
        ));
    }

    #[tokio::test]
    async fn no_zone_answering_is_unknown_and_not_a_refusal() {
        // The asymmetry: a list that is down and read as "listed" refuses
        // everyone's mail, which is an outage produced by somebody else's DNS.
        let list = FakeBlocklist::new().unreachable();
        assert!(matches!(
            check(&list, client(), &["one.example".to_string()]).await,
            Listing::Unknown { .. }
        ));
    }

    #[tokio::test]
    async fn one_zone_answering_is_an_answer() {
        // `Unknown` is for having learned nothing at all. Escalating because
        // the third list of four was slow would make the signal useless.
        let list = FakeBlocklist::new();
        assert_eq!(
            check(&list, client(), &["reachable.example".to_string()]).await,
            Listing::NotListed
        );
    }

    #[test]
    fn an_ipv4_address_is_reversed_under_the_zone() {
        assert_eq!(
            query_name("192.0.2.10".parse().unwrap(), "zen.example"),
            "10.2.0.192.zen.example"
        );
        // A trailing dot on the configured zone must not produce a doubled one:
        // `..` is not a name, and the lookup would fail for every address.
        assert_eq!(
            query_name("192.0.2.10".parse().unwrap(), "zen.example."),
            "10.2.0.192.zen.example"
        );
    }

    #[test]
    fn an_ipv6_address_is_nibble_reversed() {
        // The documented form (RFC 5782 §2.4): every nibble, least significant
        // first, dot-separated.
        let name = query_name("2001:db8::1".parse().unwrap(), "zen.example");
        assert!(name.ends_with(".zen.example"), "{name}");
        assert!(
            name.starts_with("1.0.0.0.0.0.0.0."),
            "the low nibbles are not first: {name}"
        );
        // 32 nibbles, each followed by a dot, then the zone's own dot.
        assert_eq!(name.matches('.').count(), 32 + 1, "{name}");
        assert_eq!(
            name,
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.zen.example"
        );
    }
}
