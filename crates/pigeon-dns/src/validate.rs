//! What a domain's DNS has to say before Pigeon will carry its mail.
//!
//! Every check here answers one question about published records, and every
//! answer is a [`Finding`] with a severity, an observation and — where there is
//! one — the exact record to publish. An operator reading the output should
//! never have to work out what to type.
//!
//! # Severities decide what happens, not how loud it is
//!
//! | Severity | Meaning | Effect |
//! |---|---|---|
//! | `Fatal` | mail for this domain cannot work | the domain is gated |
//! | `Error` | mail works and is likely to be refused or spam-foldered | not gated |
//! | `Warning` | works today, will break or degrade | not gated |
//! | `Info` | worth knowing | nothing |
//!
//! The line between `Fatal` and `Error` is the one that matters, and it is
//! drawn at *this host's* ability to carry the mail. A missing MX is fatal:
//! nothing will ever be delivered here. A missing DMARC record is not: mail
//! flows, and gating the domain over it would take working mail away to punish
//! a policy choice that is the operator's to make.
//!
//! # A check that cannot run is not a check that failed
//!
//! A resolver timeout produces no finding at all — it lands in
//! [`Report::unknown`] — and never a `Fatal`. Gating a domain because somebody else's DNS was slow is an
//! outage manufactured out of a hiccup, and the confirmation window in
//! `pigeon-alert` exists for the same reason one layer up.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use crate::resolver::{LookupError, SystemResolver};

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing that is true about a domain's DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// A stable identifier, so tooling can match on it without parsing prose.
    pub check: &'static str,
    /// What was observed, in the operator's terms.
    pub detail: String,
    /// The record to publish, verbatim, when there is one to publish.
    pub fix: Option<String>,
}

impl Finding {
    fn new(severity: Severity, check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            severity,
            check,
            detail: detail.into(),
            fix: None,
        }
    }

    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// Everything the checks found about one domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub domain: String,
    pub findings: Vec<Finding>,
    /// Checks that could not be run at all. Kept apart from the findings
    /// because "we could not tell" is not a result, and a caller that gated a
    /// domain on it would be gating on a resolver hiccup.
    pub unknown: Vec<String>,
}

impl Report {
    /// Whether this domain should be allowed to carry mail.
    ///
    /// Only `Fatal` gates, and only a check that actually ran can be `Fatal`.
    pub fn passes(&self) -> bool {
        !self.findings.iter().any(|f| f.severity == Severity::Fatal)
    }

    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// What Pigeon expects a domain to publish.
///
/// Supplied by the caller rather than read here, because this module knows DNS
/// and not the database: the selector and key come from `dkim_key`, and the
/// host name from configuration.
#[derive(Debug, Clone)]
pub struct Expected {
    /// This host's name, which the domain's MX should name.
    pub hostname: String,
    /// The addresses this host actually has, for the MX and PTR checks.
    pub addresses: Vec<IpAddr>,
    /// The active DKIM selector and the public key it should publish.
    pub dkim: Option<ExpectedDkim>,
}

#[derive(Debug, Clone)]
pub struct ExpectedDkim {
    pub selector: String,
    /// The full record value, as `pigeon domain show` prints it.
    pub record: String,
}

/// Check the *host* rather than a domain.
///
/// Reverse DNS is a property of the machine, not of the domains it carries, so
/// it is asked once: every domain on the host would otherwise report the same
/// finding, and an operator would fix it once and see it nine more times.
///
/// **Forward-confirmed**, which is the check receivers actually make: the
/// address must resolve back to a name, and that name must resolve to the
/// address. A PTR pointing at a name that does not point back is the shape of a
/// stale record and of a host claiming a name it does not have, and receivers
/// treat both the same way.
///
/// `Error`, never `Fatal`: mail still arrives here, and gating every domain on
/// the host because a provider has not set a PTR record would take working mail
/// away over a delivery-reputation problem.
pub async fn check_host(resolver: &SystemResolver, hostname: &str, addresses: &[IpAddr]) -> Report {
    let mut out = Report {
        domain: hostname.to_string(),
        ..Report::default()
    };

    if addresses.is_empty() {
        out.unknown
            .push("reverse dns: this host's addresses are not known".into());
        return out;
    }

    let ours = hostname.trim_end_matches('.').to_ascii_lowercase();

    for address in addresses {
        match resolver.lookup_ptr(*address).await {
            Ok(names) if names.is_empty() => out.findings.push(Finding::new(
                Severity::Error,
                "ptr.missing",
                format!("{address} has no reverse DNS; receivers treat mail from it as suspect"),
            )),
            Ok(names) => {
                let named: Vec<String> = names
                    .iter()
                    .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
                    .collect();

                if !named.contains(&ours) {
                    out.findings.push(Finding::new(
                        Severity::Error,
                        "ptr.mismatch",
                        format!(
                            "{address} reverses to {} rather than {ours}",
                            named.join(", ")
                        ),
                    ));
                    continue;
                }

                // The confirming half. A PTR that points at a name which does
                // not point back is what a stale record looks like, and what a
                // host claiming somebody else's name looks like.
                match resolver.lookup_a(&ours).await {
                    Ok(back)
                        if back
                            .iter()
                            .any(|a| a.to_canonical() == address.to_canonical()) => {}
                    Ok(_) => out.findings.push(Finding::new(
                        Severity::Error,
                        "ptr.unconfirmed",
                        format!("{ours} does not resolve back to {address}"),
                    )),
                    Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => {
                        out.findings.push(Finding::new(
                            Severity::Error,
                            "ptr.unconfirmed",
                            format!(
                                "{ours} does not resolve, so nothing confirms the reverse record"
                            ),
                        ))
                    }
                    Err(e) => out.unknown.push(format!("forward confirmation: {e}")),
                }
            }
            Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => {
                out.findings.push(Finding::new(
                    Severity::Error,
                    "ptr.missing",
                    format!(
                        "{address} has no reverse DNS; receivers treat mail from it as suspect"
                    ),
                ))
            }
            Err(e) => out.unknown.push(format!("reverse dns for {address}: {e}")),
        }
    }

    out
}

/// Run every check against one domain.
pub async fn check(resolver: &SystemResolver, domain: &str, expected: &Expected) -> Report {
    let mut report = Report {
        domain: domain.to_string(),
        ..Report::default()
    };

    check_mx(resolver, domain, expected, &mut report).await;
    check_spf(resolver, domain, &mut report).await;
    check_dmarc(resolver, domain, &mut report).await;
    check_dkim(resolver, domain, expected, &mut report).await;

    report
}

/// Does the domain point its mail here?
///
/// Fatal when it does not: no record, or records that name other hosts, means
/// nothing will ever arrive at this machine, and a domain in that state has no
/// business being marked active.
async fn check_mx(resolver: &SystemResolver, domain: &str, expected: &Expected, out: &mut Report) {
    use crate::resolver::MxLookup;

    let records = match resolver.lookup_mx(domain).await {
        Ok(r) => r,
        Err(LookupError::NoRecords(_)) => {
            out.findings.push(
                Finding::new(
                    Severity::Fatal,
                    "mx.missing",
                    format!("{domain} publishes no MX record, so no mail will reach this host"),
                )
                .with_fix(format!("{domain}. IN MX 10 {}.", expected.hostname)),
            );
            return;
        }
        Err(LookupError::NoSuchDomain(_)) => {
            out.findings.push(Finding::new(
                Severity::Fatal,
                "mx.nxdomain",
                format!("{domain} does not exist in DNS"),
            ));
            return;
        }
        Err(e) => {
            out.unknown.push(format!("mx: {e}"));
            return;
        }
    };

    let ours = expected.hostname.trim_end_matches('.').to_ascii_lowercase();
    let named: Vec<String> = records
        .iter()
        .map(|r| r.exchange.trim_end_matches('.').to_ascii_lowercase())
        .collect();

    if !named.contains(&ours) {
        out.findings.push(
            Finding::new(
                Severity::Fatal,
                "mx.elsewhere",
                format!(
                    "{domain} publishes MX records for {} and none for {ours}",
                    named.join(", ")
                ),
            )
            .with_fix(format!("{domain}. IN MX 10 {ours}.")),
        );
        return;
    }

    // Named, but is the name usable? A host whose address records are missing
    // is one nothing can connect to, which is the same outcome as no MX at all.
    match resolver.lookup_a(&ours).await {
        Ok(addrs) if addrs.is_empty() => out.findings.push(Finding::new(
            Severity::Fatal,
            "mx.no_address",
            format!("{ours} publishes no A or AAAA record, so nothing can connect to it"),
        )),
        Ok(addrs) => {
            // Not fatal when they disagree: this host may sit behind NAT or a
            // load balancer, and the address the world sees is legitimately not
            // one the machine can see. Worth saying, because it is also what a
            // stale record looks like.
            if !expected.addresses.is_empty() {
                let published: HashSet<IpAddr> = addrs.iter().map(|a| a.to_canonical()).collect();
                let mine: HashSet<IpAddr> = expected
                    .addresses
                    .iter()
                    .map(|a| a.to_canonical())
                    .collect();
                if published.is_disjoint(&mine) {
                    out.findings.push(Finding::new(
                        Severity::Warning,
                        "mx.address_mismatch",
                        format!(
                            "{ours} resolves to {} but this host has {} — correct behind NAT, \
                             and what a stale record also looks like",
                            addrs
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                            expected
                                .addresses
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
        Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => {
            out.findings.push(Finding::new(
                Severity::Fatal,
                "mx.no_address",
                format!("{ours} does not resolve, so nothing can connect to it"),
            ));
        }
        Err(e) => out.unknown.push(format!("mx address: {e}")),
    }
}

/// Does the domain authorise this host to send for it?
///
/// An error rather than fatal: mail arrives and is forwarded either way, but
/// forwarded mail with a failing SPF is what a receiver treats as
/// unauthenticated, and it is the difference between the inbox and the spam
/// folder.
async fn check_spf(resolver: &SystemResolver, domain: &str, out: &mut Report) {
    let records = match resolver.lookup_txt(domain).await {
        Ok(r) => r,
        Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => Vec::new(),
        Err(e) => {
            out.unknown.push(format!("spf: {e}"));
            return;
        }
    };

    let spf: Vec<&String> = records
        .iter()
        .filter(|r| r.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();

    match spf.len() {
        0 => out.findings.push(
            Finding::new(
                Severity::Error,
                "spf.missing",
                format!("{domain} publishes no SPF record"),
            )
            .with_fix(format!("{domain}. IN TXT \"v=spf1 mx ~all\"")),
        ),
        1 => {
            let record = spf[0];
            if record.to_ascii_lowercase().contains("+all") {
                out.findings.push(Finding::new(
                    Severity::Error,
                    "spf.permissive",
                    format!(
                        "{domain} publishes SPF `+all`, which authorises every host on the internet"
                    ),
                ));
            }
        }
        // Two SPF records is a permanent error at every receiver: the
        // specification says a domain with more than one is unevaluable, so the
        // result is neither of them.
        n => out.findings.push(Finding::new(
            Severity::Error,
            "spf.duplicate",
            format!(
                "{domain} publishes {n} SPF records; receivers treat that as a permanent error"
            ),
        )),
    }
}

/// Does the domain publish a DMARC policy?
///
/// A warning, not an error: mail is delivered without one, and receivers apply
/// their own judgement. It is here because a forwarder is exactly where DMARC
/// alignment breaks, and an operator should know whether they have a policy
/// before they discover it through a bounce.
async fn check_dmarc(resolver: &SystemResolver, domain: &str, out: &mut Report) {
    let name = format!("_dmarc.{domain}");
    let records = match resolver.lookup_txt(&name).await {
        Ok(r) => r,
        Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => Vec::new(),
        Err(e) => {
            out.unknown.push(format!("dmarc: {e}"));
            return;
        }
    };

    let found: Vec<&String> = records
        .iter()
        .filter(|r| r.to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();

    if found.is_empty() {
        out.findings.push(
            Finding::new(
                Severity::Warning,
                "dmarc.missing",
                format!("{domain} publishes no DMARC record"),
            )
            .with_fix(format!(
                "_dmarc.{domain}. IN TXT \"v=DMARC1; p=none; rua=mailto:postmaster@{domain}\""
            )),
        );
        return;
    }

    if found[0].to_ascii_lowercase().contains("p=reject") {
        out.findings.push(Finding::new(
            Severity::Info,
            "dmarc.reject",
            format!(
                "{domain} publishes p=reject; forwarded mail must be rewritten and signed by \
                 this host to stay aligned"
            ),
        ));
    }
}

/// Is the active DKIM key published, and is it the one this host signs with?
///
/// Fatal when the domain forwards under `rewrite_from`, because a rewritten
/// `From:` that cannot be verified fails DMARC on a domain Pigeon controls —
/// which is worse than not rewriting. That decision is the caller's, though,
/// and is expressed by whether a key is expected at all.
async fn check_dkim(
    resolver: &SystemResolver,
    domain: &str,
    expected: &Expected,
    out: &mut Report,
) {
    let Some(dkim) = &expected.dkim else {
        return;
    };

    let name = format!("{}._domainkey.{domain}", dkim.selector);
    let records = match resolver.lookup_txt(&name).await {
        Ok(r) => r,
        Err(LookupError::NoRecords(_) | LookupError::NoSuchDomain(_)) => Vec::new(),
        Err(e) => {
            out.unknown.push(format!("dkim: {e}"));
            return;
        }
    };

    if records.is_empty() {
        out.findings.push(
            Finding::new(
                Severity::Error,
                "dkim.missing",
                format!("{name} publishes no record, so nothing this host signs will verify"),
            )
            .with_fix(format!("{name}. IN TXT \"{}\"", dkim.record)),
        );
        return;
    }

    // Compared on the key material rather than the whole string: the record is
    // published as several quoted chunks, tag order is not significant, and a
    // provider may add or reorder tags of its own. What must match is `p=`.
    let published = records.iter().find_map(|r| tag(r, "p"));
    let ours = tag(&dkim.record, "p");

    match (published, ours) {
        (Some(published), Some(ours)) if published == ours => {}
        (Some(_), Some(_)) => out.findings.push(
            Finding::new(
                Severity::Error,
                "dkim.mismatch",
                format!("{name} publishes a different key from the one this host signs with"),
            )
            .with_fix(format!("{name}. IN TXT \"{}\"", dkim.record)),
        ),
        _ => out.findings.push(Finding::new(
            Severity::Error,
            "dkim.unreadable",
            format!("{name} publishes a record with no usable p= tag"),
        )),
    }
}

/// One tag's value out of a DKIM-style record.
fn tag(record: &str, name: &str) -> Option<String> {
    record.split(';').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().replace([' ', '\t'], ""))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_fatal_finding_gates_a_domain() {
        // The line the whole severity scale exists to draw. A missing DMARC
        // record does not stop mail arriving; taking the domain out of service
        // for it would be punishing a policy choice that is the operator's.
        let mut r = Report::default();
        r.findings
            .push(Finding::new(Severity::Error, "spf.missing", "no SPF"));
        r.findings
            .push(Finding::new(Severity::Warning, "dmarc.missing", "no DMARC"));
        assert!(r.passes());

        r.findings
            .push(Finding::new(Severity::Fatal, "mx.missing", "no MX"));
        assert!(!r.passes());
    }

    #[test]
    fn an_unknown_check_is_not_a_failure() {
        // A resolver timeout is not evidence about the domain. Gating on it
        // would manufacture an outage out of somebody else's hiccup.
        let r = Report {
            domain: "example.com".into(),
            findings: Vec::new(),
            unknown: vec!["mx: resolver failed".into()],
        };
        assert!(r.passes(), "an unrunnable check gated a domain");
        assert_eq!(r.worst(), None);
    }

    #[test]
    fn a_dkim_tag_survives_chunking_and_whitespace() {
        // Published records are split into quoted chunks and often re-wrapped
        // by the provider's UI, so a whole-string comparison reports a mismatch
        // for a record that is correct.
        let ours = "v=DKIM1; k=rsa; p=MIIBIjANBg";
        let published = "v=DKIM1;k=rsa;t=s;p=MIIB Ij ANBg";
        assert_eq!(tag(ours, "p"), tag(published, "p"));

        // And a genuinely different key still differs.
        assert_ne!(tag(ours, "p"), tag("v=DKIM1; p=SOMETHINGELSE", "p"));
    }

    #[test]
    fn severities_order_worst_last() {
        let mut r = Report::default();
        r.findings
            .push(Finding::new(Severity::Info, "dmarc.reject", "policy"));
        r.findings
            .push(Finding::new(Severity::Error, "spf.missing", "no SPF"));
        assert_eq!(r.worst(), Some(Severity::Error));
    }
}
