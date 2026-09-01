//! Periodic DNS checks, domain gating, and the alerts that follow.
//!
//! # Why gating is per domain and never per process
//!
//! A domain whose records regress stops accepting its own mail; the daemon
//! keeps running and every other domain is unaffected (`ARCHITECTURE.md` §5.1).
//! If DNS validation gated startup instead, a transient resolver outage would
//! take down mail for every domain on the host at once — and one misconfigured
//! domain out of forty must never be a total outage.
//!
//! The same asymmetry decides the direction of every judgement here. A check
//! that could not run is not a failure: `pigeon-dns`'s report keeps those apart,
//! and only a `Fatal` finding gates.
//!
//! # Alerts are decided here and sent out of band
//!
//! Whether to send is `pigeon-alert`'s decision — transitions, confirmation,
//! cooldown, breaker. How to send is this module's: straight to the recipient's
//! MX through the delivery client, never through the routing engine. Routing an
//! alert normally would let it be caught by a catch-all, loop between two
//! managed domains, or be gated by the very domain it concerns.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pigeon_alert::{Alert, AlertKind, Policy, Tracker};
use pigeon_dns::MxLookup;
use pigeon_dns::validate::{Expected, ExpectedDkim, Report};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often every domain is checked.
///
/// Fifteen minutes: DNS changes are made by people, propagate over minutes, and
/// the confirmation window multiplies this into how long a real regression
/// takes to be noticed. Checking every minute would multiply the query load by
/// fifteen to learn the same thing.
const INTERVAL: Duration = Duration::from_secs(15 * 60);

pub struct Health {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

/// Everything one cycle needs.
pub struct HealthConfig<R: MxLookup> {
    pub db: std::path::PathBuf,
    pub hostname: String,
    /// This host's own addresses, for the reverse-DNS check.
    pub addresses: Vec<std::net::IpAddr>,
    pub resolver: Arc<pigeon_dns::SystemResolver>,
    pub policy: Policy,
    /// Where alerts are sent, and as whom. `None` disables alerting entirely,
    /// which is the default: an operator who has not configured a recipient has
    /// not asked to be mailed.
    pub alerts: Option<AlertDelivery<R>>,
    /// The inbound certificate to watch, if one is configured.
    pub certificate: Option<Certificate>,
}

/// The certificate this host serves, and where it came from.
pub struct Certificate {
    pub certificate: std::path::PathBuf,
    pub private_key: std::path::PathBuf,
    /// The live configuration, replaced in place when the files change.
    pub serving: pigeon_smtp::tls::Serving,
}

/// How close to expiry is worth an alert.
///
/// Two weeks: long enough that a renewal timer which has quietly stopped can be
/// noticed and fixed by a person who is not on call, and short enough that it
/// is not background noise for the other fifty weeks.
const EXPIRY_WARNING: i64 = 14 * 24 * 60 * 60;

/// How an alert reaches the operator.
pub struct AlertDelivery<R: MxLookup> {
    /// The address alerts are sent *as*. Validated at startup not to be on a
    /// domain this host carries — an alert about a broken domain cannot be sent
    /// from that domain, because it is destroyed by the fault it reports.
    pub identity: String,
    pub to: String,
    pub forwarding: crate::Forwarding<R>,
}

impl Health {
    pub fn start<R: MxLookup + 'static>(config: HealthConfig<R>) -> Self {
        let (stop, mut stopped) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let mut tracker = Tracker::new();

            loop {
                if *stopped.borrow_and_update() {
                    return;
                }

                cycle(&config, &mut tracker).await;

                tokio::select! {
                    () = tokio::time::sleep(INTERVAL) => {}
                    _ = stopped.changed() => return,
                }
            }
        });

        Self { stop, handle }
    }

    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    pub fn supervise(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            match self.handle.await {
                Ok(()) => tracing::debug!("the health worker exited"),
                Err(e) if e.is_panic() => {
                    tracing::error!(error = %e, "the health worker panicked; domains are no longer checked")
                }
                Err(_) => {}
            }
        })
    }
}

/// One pass over every domain.
async fn cycle<R: MxLookup>(config: &HealthConfig<R>, tracker: &mut Tracker) {
    let Ok(conn) = pigeon_db::open(&config.db) else {
        tracing::error!("the health worker cannot open the database");
        return;
    };

    let domains = match pigeon_db::repo::list_domains(&conn) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "the health worker cannot list domains");
            return;
        }
    };

    let mut results = Vec::with_capacity(domains.len());
    let mut reports = Vec::with_capacity(domains.len());

    for domain in &domains {
        // Only domains that have been onboarded. One still in `new` or
        // `pending_dns` is being set up by an operator who is watching, and
        // gating it would be reporting a fault they already know about.
        if domain.status != "active" && domain.status != "error" {
            continue;
        }

        let expected = Expected {
            hostname: config.hostname.clone(),
            addresses: config.addresses.clone(),
            dkim: pigeon_db::repo::dkim_keys_for(&conn, &domain.name)
                .unwrap_or_default()
                .into_iter()
                .filter(|k| k.state == "active")
                .map(|k| ExpectedDkim {
                    selector: k.selector,
                    record: if k.algorithm == "ed25519" {
                        format!("v=DKIM1; k=ed25519; p={}", k.public_key)
                    } else {
                        format!("v=DKIM1; k=rsa; p={}", k.public_key)
                    },
                })
                .collect(),
        };

        let report =
            pigeon_dns::validate::check(config.resolver.as_ref(), &domain.name, &expected).await;
        results.push((domain.name.clone(), report.passes()));
        reports.push(report);
    }

    if results.is_empty() {
        return;
    }

    // The database is told about every domain, whatever the alert policy
    // decides: gating is about whether mail is accepted, and suppression is
    // about how much mail Pigeon sends *itself*. Conflating them would leave a
    // broken domain serving because the operator had already been told.
    for (name, ok) in &results {
        match pigeon_db::repo::set_domain_health(&conn, name, *ok) {
            Ok(true) if *ok => {
                tracing::info!(domain = %name, "domain recovered; accepting mail again")
            }
            Ok(true) => tracing::warn!(domain = %name, "domain gated: its DNS no longer passes"),
            Ok(false) => {}
            Err(e) => tracing::error!(domain = %name, error = %e, "cannot record domain health"),
        }
    }

    // The certificate is checked in the same cycle: a renewal is a file that
    // changed underneath a running process, and loading once at startup means
    // serving an expired certificate until somebody restarts the daemon.
    let certificate_alert = check_certificate(config);

    let decision = tracker.cycle(&results, &config.policy, Instant::now());

    for (domain, why) in &decision.suppressed {
        tracing::debug!(%domain, ?why, "alert suppressed");
    }

    let Some(delivery) = &config.alerts else {
        return;
    };

    let mut send_list = decision.send.clone();
    send_list.extend(certificate_alert);

    for alert in &send_list {
        let report = reports.iter().find(|r| r.domain == alert.domain);
        if let Err(e) = send(delivery, alert, report).await {
            // The channel that reports failures can itself fail, and it shares
            // a failure domain with what it monitors. Logged loudly because the
            // silence otherwise looks exactly like health.
            tracing::error!(domain = %alert.domain, error = %e, "could not send an alert");
        }
    }
}

/// Reload a renewed certificate, and say when one is about to expire.
///
/// Reloading is unconditional and cheap: a certificate that parses replaces the
/// live one, and a certificate that does not is left alone with a loud message.
/// The alternative — refusing to serve TLS because a renewal wrote a bad file —
/// would turn a broken timer into an outage rather than a warning.
fn check_certificate<R: MxLookup>(config: &HealthConfig<R>) -> Option<Alert> {
    let cert = config.certificate.as_ref()?;

    match pigeon_smtp::tls::load(&cert.certificate, &cert.private_key) {
        Ok(loaded) => cert.serving.replace(loaded),
        Err(e) => {
            tracing::error!(
                error = %e,
                "the TLS certificate could not be reloaded; still serving the previous one"
            );
            return None;
        }
    }

    let expires = match pigeon_smtp::tls::expires_at(&cert.certificate) {
        Ok(at) => at,
        Err(e) => {
            tracing::warn!(error = %e, "cannot read the certificate's expiry");
            return None;
        }
    };

    let remaining = expires - crate::unix_now();
    if remaining > EXPIRY_WARNING {
        return None;
    }

    let days = remaining / 86_400;
    tracing::warn!(days, "the TLS certificate is close to expiry");
    Some(Alert {
        kind: AlertKind::CertificateExpiring,
        // Not about a domain: the certificate belongs to the host.
        domain: String::new(),
        detail: if remaining <= 0 {
            "the TLS certificate has expired; senders that try STARTTLS are being refused".into()
        } else {
            format!("the TLS certificate expires in {days} days")
        },
    })
}

/// Send one alert, straight to the operator's MX.
async fn send<R: MxLookup>(
    delivery: &AlertDelivery<R>,
    alert: &Alert,
    report: Option<&Report>,
) -> Result<(), crate::ForwardError> {
    let body = render(&delivery.identity, &delivery.to, alert, report);
    // An empty return path: an alert is a notification, and a bounce for one
    // must not produce another alert about the bounce.
    crate::forward(&delivery.forwarding, 0, &delivery.to, "", body.as_bytes())
        .await
        .map(|_| ())
}

/// The message an operator receives.
///
/// The findings are quoted verbatim from `pigeon domain check`, including the
/// record to publish: an alert that says "DNS is broken" and makes the operator
/// go and run the command themselves has wasted the trip.
fn render(from: &str, to: &str, alert: &Alert, report: Option<&Report>) -> String {
    let subject = match alert.kind {
        AlertKind::DomainGated => format!("[pigeon] {} has stopped accepting mail", alert.domain),
        AlertKind::DomainRecovered => format!("[pigeon] {} is accepting mail again", alert.domain),
        AlertKind::ResolverSuspect => "[pigeon] DNS checks are failing across domains".into(),
        AlertKind::CertificateExpiring => "[pigeon] the TLS certificate is expiring".into(),
        AlertKind::QueueBacklog => "[pigeon] the queue is growing".into(),
        AlertKind::DiskPressure => "[pigeon] the spool filesystem is filling up".into(),
    };

    let mut body = String::new();
    body.push_str(&format!("From: <{from}>\r\n"));
    body.push_str(&format!("To: <{to}>\r\n"));
    body.push_str(&format!("Subject: {subject}\r\n"));
    body.push_str("MIME-Version: 1.0\r\n");
    body.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    body.push_str("Auto-Submitted: auto-generated\r\n\r\n");

    body.push_str(&alert.detail);
    body.push_str("\r\n");

    if let Some(report) = report {
        body.push_str("\r\nWhat the checks found:\r\n\r\n");
        for f in &report.findings {
            body.push_str(&format!("  {:<8} {}\r\n", f.severity.as_str(), f.detail));
            if let Some(fix) = &f.fix {
                body.push_str(&format!("           publish: {fix}\r\n"));
            }
        }
        for u in &report.unknown {
            body.push_str(&format!("  unknown  could not be checked: {u}\r\n"));
        }
    }

    body.push_str("\r\nThis is the convenient channel, not the authoritative one:\r\n");
    body.push_str("email about email infrastructure shares a failure domain with it.\r\n");
    body.push_str("`pigeon domains check` is the source of truth.\r\n");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(kind: AlertKind, domain: &str) -> Alert {
        Alert {
            kind,
            domain: domain.into(),
            detail: "its DNS records no longer pass".into(),
        }
    }

    #[test]
    fn an_alert_carries_the_records_to_publish() {
        // An alert that says "DNS is broken" and makes the operator go and run
        // the command themselves has wasted the trip.
        use pigeon_dns::validate::{Finding, Severity};

        let report = Report {
            domain: "example.com".into(),
            findings: vec![Finding {
                severity: Severity::Fatal,
                check: "mx.missing",
                detail: "example.com publishes no MX record".into(),
                fix: Some("example.com. IN MX 10 mx.pigeon.test.".into()),
            }],
            unknown: Vec::new(),
        };

        let body = render(
            "alerts@pigeon.test",
            "operator@example.net",
            &alert(AlertKind::DomainGated, "example.com"),
            Some(&report),
        );

        assert!(body.contains("Subject: [pigeon] example.com has stopped accepting mail"));
        assert!(body.contains("publishes no MX record"));
        assert!(
            body.contains("example.com. IN MX 10 mx.pigeon.test."),
            "the alert does not say what to publish:\n{body}"
        );
        // Marked so mailing lists and vacation responders leave it alone.
        assert!(body.contains("Auto-Submitted: auto-generated"));
    }

    #[test]
    fn an_alert_says_it_is_not_the_authoritative_channel() {
        // Email alerting about email infrastructure shares a failure domain
        // with the thing it monitors, and the silence looks like health.
        let body = render(
            "alerts@pigeon.test",
            "operator@example.net",
            &alert(AlertKind::DomainRecovered, "example.com"),
            None,
        );
        assert!(body.contains("pigeon domains check"));
    }
}
