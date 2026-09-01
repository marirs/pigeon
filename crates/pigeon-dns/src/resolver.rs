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

    /// Resolve a mail exchanger to the addresses a connection would be made to.
    ///
    /// Separate from `lookup_mx` because it answers a different question, and
    /// on this trait because the delivery path needs both from one object — the
    /// addresses are what loop detection compares, and resolving them anywhere
    /// else would mean the address checked and the address connected to could
    /// differ.
    ///
    /// The default is the system resolver by way of `getaddrinfo`, which is
    /// exactly what `TcpStream::connect((host, port))` did before this existed.
    /// Deliberately *not* hickory: `/etc/hosts` is how small deployments name
    /// hosts that no DNS server knows, and a resolver that ignored it would
    /// stop delivering to them.
    fn lookup_addresses(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = std::io::Result<Vec<std::net::SocketAddr>>> + Send {
        let host = host.to_string();
        async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addrs| addrs.collect())
        }
    }
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

impl SystemResolver {
    /// A resolver with no name servers, which therefore answers nothing.
    ///
    /// For deterministic tests. `from_system` reads `/etc/resolv.conf`, which
    /// makes what a lookup returns a property of the machine the test runs on —
    /// and two verification tests in this repository have already failed for
    /// exactly that reason. Every lookup through this one fails in the resolver
    /// without a packet leaving the process, which is the "could not tell"
    /// answer the blocklist path is built to handle.
    ///
    /// Production keeps `from_system` and keeps failing when it cannot be
    /// built: a daemon resolving through a resolver that answers nothing would
    /// defer every delivery.
    pub fn offline() -> Self {
        use hickory_resolver::config::ResolverConfig;
        let inner = hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::default(),
            hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
        )
        .build()
        .expect("a resolver with no name servers always builds");
        Self { inner }
    }

    /// The names an address reverses to.
    pub async fn lookup_ptr(&self, address: std::net::IpAddr) -> Result<Vec<String>, LookupError> {
        let answer = self
            .inner
            .reverse_lookup(address)
            .await
            .map_err(|e| classify(e, &address.to_string()))?;

        Ok(answer
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::PTR(ptr) => Some(ptr.to_string()),
                _ => None,
            })
            .collect())
    }

    /// Look up the `TXT` records for a name.
    ///
    /// Chunks are joined without a separator, which is what every consumer of
    /// TXT does: a long record is published as several quoted strings and means
    /// the concatenation, not the list.
    pub async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, LookupError> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let answer = self
            .inner
            .txt_lookup(fqdn.as_str())
            .await
            .map_err(|e| classify(e, name))?;

        // Filtered by rdata like the MX path, and for the same reason: the
        // answer section carries whatever the resolver followed to get here.
        Ok(answer
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    }

    /// Look up the `A` and `AAAA` records for a name.
    ///
    /// Used by the blocklist check, where the *values* are the answer rather
    /// than somewhere to connect: a list encodes why an address is listed in
    /// the address it returns.
    pub async fn lookup_a(&self, name: &str) -> Result<Vec<std::net::IpAddr>, LookupError> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };

        let answer = self
            .inner
            .lookup_ip(fqdn.as_str())
            .await
            .map_err(|e| classify(e, name))?;

        Ok(answer.iter().collect())
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

        let answer = self
            .inner
            .mx_lookup(fqdn.as_str())
            .await
            .map_err(|e| classify(e, domain))?;

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

/// Turn a resolver error into a Pigeon one.
///
/// The distinction that matters is NXDOMAIN versus NODATA, and it cannot be
/// read from the error text: hickory reports both as `NoRecordsFound`, whose
/// `Display` is "no records found for {query}" either way. Matching on that
/// string made every MX-less domain look non-existent, which is permanent —
/// so the implicit-MX fallback below could never fire, and mail to any domain
/// with an A record but no MX was refused for good.
///
/// The response code carried on the error says which it actually was.
fn classify<E: std::error::Error + 'static>(e: E, domain: &str) -> LookupError {
    use hickory_resolver::net::DnsError;
    use hickory_resolver::proto::op::ResponseCode;

    // Walked rather than matched directly: the resolver wraps the semantic DNS
    // error in a transport error, and the wrapping is not part of its stable
    // surface. Downcasting along the chain finds it however it is nested.
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(&e);
    while let Some(err) = current {
        if let Some(dns) = err.downcast_ref::<DnsError>() {
            return match dns {
                // The distinction the whole function exists for. Both arrive as
                // NoRecordsFound and both stringify identically, so only the
                // response code separates "this name does not exist" from
                // "this name exists and publishes no MX".
                DnsError::NoRecordsFound(no) => match no.response_code {
                    ResponseCode::NXDomain => LookupError::NoSuchDomain(domain.to_string()),
                    _ => LookupError::NoRecords(domain.to_string()),
                },
                DnsError::ResponseCode(ResponseCode::NXDomain) => {
                    LookupError::NoSuchDomain(domain.to_string())
                }
                _ => LookupError::Resolver(e.to_string()),
            };
        }
        current = err.source();
    }

    // Anything unrecognised stays transient. The two mistakes are not
    // symmetric: retrying a dead domain wastes queue time, while treating a
    // resolver fault as permanent bounces mail that would have delivered.
    LookupError::Resolver(e.to_string())
}

/// A resolver with canned answers, for tests.
#[derive(Debug, Default, Clone)]
pub struct FakeResolver {
    answers: std::collections::HashMap<String, Result<Vec<MxRecord>, LookupError>>,
    /// Addresses for named hosts. A host with no entry falls through to the
    /// system resolver, which resolves the address literals most tests use.
    addresses: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
}

impl FakeResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, domain: &str, records: Vec<MxRecord>) -> Self {
        self.answers
            .insert(domain.to_ascii_lowercase(), Ok(records));
        self
    }

    pub fn failing(mut self, domain: &str, error: LookupError) -> Self {
        self.answers.insert(domain.to_ascii_lowercase(), Err(error));
        self
    }

    /// Give a mail exchanger a fixed address list, in order.
    ///
    /// Order matters to what the caller does with it — a delivery tries them in
    /// the order given — so it is preserved rather than sorted.
    pub fn with_addresses(mut self, host: &str, addresses: Vec<std::net::IpAddr>) -> Self {
        self.addresses.insert(host.to_ascii_lowercase(), addresses);
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

    async fn lookup_addresses(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<Vec<std::net::SocketAddr>> {
        match self.addresses.get(&host.to_ascii_lowercase()) {
            Some(addrs) => Ok(addrs
                .iter()
                .map(|a| std::net::SocketAddr::new(*a, port))
                .collect()),
            // Unmapped names fall through, so a test that only cares about MX
            // ordering can keep using address literals.
            None => tokio::net::lookup_host((host, port))
                .await
                .map(|addrs| addrs.collect()),
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
            vec![
                MxRecord::new(20, "backup.example.net."),
                MxRecord::new(10, "mx.example.net."),
            ],
        );

        let records = r.lookup_mx("EXAMPLE.COM").await.unwrap();
        assert_eq!(
            order_hosts(&records, 0).unwrap(),
            ["mx.example.net", "backup.example.net"]
        );
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
        let r =
            FakeResolver::new().failing("example.com", LookupError::Resolver("timed out".into()));
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
