//! `pigeon domain check` and `pigeon domains check`.
//!
//! What a domain's DNS says, compared with what this host needs it to say.
//! The output is written to be acted on: every finding names what was observed
//! and, where one exists, the exact record to publish. An operator should never
//! have to work out what to type from a description of what is wrong.
//!
//! # Exit codes carry the verdict
//!
//! Because this is what a monitoring system reads, and parsing prose to decide
//! whether to page someone is how monitoring breaks. A `Fatal` finding exits
//! non-zero; anything less exits zero, because mail still flows.

use pigeon_dns::validate::{Expected, ExpectedDkim, Report, Severity};

/// Check one domain.
pub fn one(
    conn: &rusqlite::Connection,
    config: &pigeon_config::Config,
    domain: &str,
    json: bool,
) -> anyhow::Result<u8> {
    let report = run(conn, config, &[domain.to_ascii_lowercase()])?;
    let report = report.into_iter().next().expect("one domain, one report");

    if json {
        crate::json::ok(render_json(&report));
    } else {
        print_report(&report);
    }
    Ok(verdict(std::slice::from_ref(&report)))
}

/// Check every domain.
pub fn all(
    conn: &rusqlite::Connection,
    config: &pigeon_config::Config,
    json: bool,
) -> anyhow::Result<u8> {
    let names: Vec<String> = pigeon_db::repo::list_domains(conn)?
        .into_iter()
        .map(|d| d.name)
        .collect();

    if names.is_empty() {
        if json {
            crate::json::ok(serde_json::json!({ "domains": [] }));
        } else {
            println!("No domains yet.\n  pigeon domain add example.com --to you@example.net");
        }
        return Ok(crate::exit::OK);
    }

    let reports = run(conn, config, &names)?;

    if json {
        crate::json::ok(serde_json::json!({
            "domains": reports.iter().map(render_json).collect::<Vec<_>>(),
        }));
    } else {
        for (n, report) in reports.iter().enumerate() {
            if n > 0 {
                println!();
            }
            print_report(report);
        }
    }
    Ok(verdict(&reports))
}

/// Resolve and check, on a runtime of its own.
///
/// The CLI is otherwise synchronous, and making it async everywhere for one
/// command would be paying for the whole tool to look like a daemon.
fn run(
    conn: &rusqlite::Connection,
    config: &pigeon_config::Config,
    domains: &[String],
) -> anyhow::Result<Vec<Report>> {
    let expectations: Vec<(String, Expected)> = domains
        .iter()
        .map(|name| {
            // The active key, if the domain has one. A domain with no key
            // signs nothing, so there is no record to compare and no finding to
            // make — silence rather than a complaint about an absence nobody
            // asked for.
            let dkim = pigeon_db::repo::dkim_keys_for(conn, name)
                .ok()
                .and_then(|keys| {
                    keys.into_iter()
                        .find(|k| k.state == "active")
                        .map(|k| ExpectedDkim {
                            selector: k.selector,
                            record: format!("v=DKIM1; k=rsa; p={}", k.public_key),
                        })
                });
            (
                name.clone(),
                Expected {
                    hostname: config.hostname.clone(),
                    // Left to the caller to fill in when it knows: the CLI does
                    // not bind a listener, so what it could offer here is a
                    // guess about interfaces, and a guess would produce a
                    // mismatch warning nobody can act on.
                    addresses: Vec::new(),
                    dkim,
                },
            )
        })
        .collect();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let resolver = pigeon_dns::SystemResolver::from_system()
            .map_err(|e| anyhow::anyhow!("cannot build a resolver: {e}"))?;

        let mut reports = Vec::with_capacity(expectations.len());
        for (name, expected) in &expectations {
            reports.push(pigeon_dns::validate::check(&resolver, name, expected).await);
        }
        Ok(reports)
    })
}

/// Non-zero when any domain cannot carry mail.
///
/// Only `Fatal`. A missing SPF record is worth fixing and is not worth waking
/// somebody at three in the morning, and an exit code that cannot tell the
/// difference gets ignored.
fn verdict(reports: &[Report]) -> u8 {
    if reports.iter().all(Report::passes) {
        crate::exit::OK
    } else {
        crate::exit::FAILED
    }
}

fn render_json(report: &Report) -> serde_json::Value {
    serde_json::json!({
        "domain": report.domain,
        "passes": report.passes(),
        "findings": report.findings.iter().map(|f| serde_json::json!({
            "severity": f.severity.as_str(),
            "check": f.check,
            "detail": f.detail,
            "fix": f.fix,
        })).collect::<Vec<_>>(),
        // Reported rather than folded into the findings: a check that could not
        // run is not a check that failed, and a consumer deciding whether to
        // alert needs to see the difference.
        "unchecked": report.unknown,
    })
}

fn print_report(report: &Report) {
    println!("{}\n", report.domain);

    if report.findings.is_empty() && report.unknown.is_empty() {
        println!("  Everything this host needs is published.");
        return;
    }

    // Worst first: the thing that stops mail is the thing to read.
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    for f in findings {
        println!("  {:<8} {}", label(f.severity), f.detail);
        if let Some(fix) = &f.fix {
            println!("           publish: {fix}");
        }
    }

    for u in &report.unknown {
        println!("  {:<8} could not be checked: {u}", label(Severity::Info));
    }

    if !report.passes() {
        println!("\n  This domain cannot carry mail until the fatal findings are fixed.");
    }
}

fn label(severity: Severity) -> &'static str {
    match severity {
        Severity::Fatal => "FATAL",
        Severity::Error => "ERROR",
        Severity::Warning => "WARN",
        Severity::Info => "INFO",
    }
}
