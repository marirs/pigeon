//! Asking DNS for MX records.
//!
//! Deliberately thin. Everything that decides anything lives in [`crate::mx`],
//! against records supplied by the caller, so it can be tested without a
//! network. This module only turns a resolver's answer into those records —
//! which also means a resolver library change touches one file.
//!
//! The [`MxLookup`] trait exists so that delivery can be driven by a fake in
//! tests. Depending on live DNS to test a queue would make the test suite slow,
//! flaky, and dependent on somebody else's zone file.

use std::future::Future;

use crate::mx::MxRecord;

/// Why an MX lookup did not produce records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// The name does not exist. Permanent: no amount of retrying invents it.
    NoSuchDomain(String),
    /// The name exists but publishes no MX. The caller should fall back to an
    /// address lookup, since a domain with only an A record still takes mail.
    NoRecords(String),
    /// The resolver failed. Transient by default — see below.
    Resolver(String),
}

impl LookupError {
    /// Whether to give up.
    ///
    /// Only a confirmed non-existent domain is permanent. Everything else
    /// errs toward retrying, because the two mistakes are not symmetric:
    /// retrying a dead domain wastes a few days of queue, while treating a
    /// resolver hiccup as permanent bounces mail that would have delivered —
    /// and Pigeon keeps no copy to reconsider.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::NoSuchDomain(_))
    }
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchDomain(d) => write!(f, "no such domain: {d}"),
            Self::NoRecords(d) => write!(f, "no MX records for {d}"),
            Self::Resolver(e) => write!(f, "resolver error: {e}"),
        }
    }
}

impl std::error::Error for LookupError {}

/// Somewhere to ask for MX records.
pub trait MxLookup: Send + Sync {
    fn lookup_mx(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<MxRecord>, LookupError>> + Send;
}

/// A live resolver backed by the system configuration.
#[derive(Clone)]
pub struct SystemResolver {
    inner: hickory_resolver::TokioResolver,
}

impl SystemResolver {
    /// Build from `/etc/resolv.conf`.
    ///
    /// A resolver that cannot be constructed is local misconfiguration and
    /// stops startup, unlike a resolver that is merely failing to answer.
    pub fn from_system() -> Result<Self, LookupError> {
        let inner = hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| LookupError::Resolver(e.to_string()))?
            .build()
            .map_err(|e| LookupError::Resolver(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl MxLookup for SystemResolver {
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, LookupError> {
        // A trailing dot makes the query absolute, so the resolver's search
        // list cannot silently turn `example.com` into `example.com.lan`.
        let fqdn = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        };

        let answer = self.inner.mx_lookup(fqdn.as_str()).await.map_err(|e| {
            let text = e.to_string();
            // Classified on the error text because the resolver's error kinds
            // are not part of its stable surface. Getting this wrong is safe
            // in one direction only, so anything unrecognised stays transient.
            if text.contains("no record") || text.contains("NXDomain") {
                LookupError::NoSuchDomain(domain.to_string())
            } else {
                LookupError::Resolver(text)
            }
        })?;

        // `Lookup` carries raw records rather than a typed MX view, so the
        // answer section is filtered by rdata. Anything that is not an MX —
        // a CNAME the resolver followed, say — is skipped rather than
        // mistaken for a mail exchange.
        let records: Vec<MxRecord> = answer
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::MX(mx) => {
                    Some(MxRecord::new(mx.preference, mx.exchange.to_string()))
                }
                _ => None,
            })
            .collect();

        if records.is_empty() {
            return Err(LookupError::NoRecords(domain.to_string()));
        }
        Ok(records)
    }
}

/// A resolver with canned answers, for tests.
#[derive(Debug, Default, Clone)]
pub struct FakeResolver {
    answers: std::collections::HashMap<String, Result<Vec<MxRecord>, LookupError>>,
}

impl FakeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, domain: &str, records: Vec<MxRecord>) -> Self {
        self.answers.insert(domain.to_ascii_lowercase(), Ok(records));
        self
    }

    pub fn failing(mut self, domain: &str, error: LookupError) -> Self {
        self.answers.insert(domain.to_ascii_lowercase(), Err(error));
        self
    }
}

impl MxLookup for FakeResolver {
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, LookupError> {
        match self.answers.get(&domain.to_ascii_lowercase()) {
            Some(r) => r.clone(),
            None => Err(LookupError::NoSuchDomain(domain.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mx::order_hosts;

    #[tokio::test]
    async fn fake_resolver_feeds_the_ordering() {
        let r = FakeResolver::new().with(
            "example.com",
            vec![MxRecord::new(20, "backup.example.net."), MxRecord::new(10, "mx.example.net.")],
        );

        let records = r.lookup_mx("EXAMPLE.COM").await.unwrap();
        assert_eq!(order_hosts(&records, 0).unwrap(), ["mx.example.net", "backup.example.net"]);
    }

    #[tokio::test]
    async fn unknown_domain_is_permanent() {
        let r = FakeResolver::new();
        let e = r.lookup_mx("nowhere.invalid").await.unwrap_err();
        assert!(e.is_permanent());
    }

    #[tokio::test]
    async fn resolver_trouble_is_not_permanent() {
        // The asymmetry that matters: a retry costs queue time, a wrong bounce
        // costs the message.
        let r = FakeResolver::new()
            .failing("example.com", LookupError::Resolver("timed out".into()));
        let e = r.lookup_mx("example.com").await.unwrap_err();
        assert!(!e.is_permanent());
    }

    #[tokio::test]
    async fn absent_mx_is_distinct_from_absent_domain() {
        // One means fall back to an address lookup; the other means give up.
        let r = FakeResolver::new()
            .failing("example.com", LookupError::NoRecords("example.com".into()));
        let e = r.lookup_mx("example.com").await.unwrap_err();
        assert!(!e.is_permanent());
        assert!(matches!(e, LookupError::NoRecords(_)));
    }
}
