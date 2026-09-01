//! The `pigeon` command line interface.
//!
//! # Shape
//!
//! Every command reads `pigeon <noun> <verb> [target] [arguments]`.
//!
//! Nouns are few and stable. Verbs repeat across nouns — `list`, `add`,
//! `remove`, `show`, `check`, `test` — so learning one noun teaches the rest.
//! Where a verb would only make sense for one noun, that is a sign the noun is
//! wrong.
//!
//! Singular acts on one thing, plural on all of them:
//!
//! ```text
//! pigeon domain check example.com   # one
//! pigeon domains check              # all
//! ```
//!
//! Forwarding rules — aliases, catch-all, reject — all live under `alias`,
//! because they are one concept with a precedence order rather than three
//! unrelated features.
//!
//! # Help is part of the interface
//!
//! Three rules, applied without exception:
//!
//! 1. **A bare noun prints its own help and exits zero.** `pigeon domain` is
//!    someone asking what they can do to a domain, not a usage error.
//! 2. **Every help page ends with worked examples.** A syntax summary alone
//!    leaves the reader guessing at argument order, which is the actual
//!    question they had.
//! 3. **Every error names the fix.** Not just what was wrong — the command that
//!    puts it right, or the near-miss that was probably intended.
//!
//! Commands with an obvious next step print it. Adding a domain says to check
//! it; a failing check prints the record to publish. The operator should never
//! have to consult documentation to find out what to do next.
//!
//! # Where commands run
//!
//! Read commands open SQLite read-only. Mutating commands open it for writing
//! and go through `pigeon_route::mutate`, which applies the change, builds and
//! validates the prospective snapshot *inside the same transaction*, rolls back
//! if it will not serve, commits, and only then publishes.
//!
//! A running daemon picks the change up on its own: it polls `data_version`
//! and republishes when the routing input actually changed, so the CLI does not
//! signal it and does not need to. What the CLI does say is that it is a poll
//! rather than a push: an operator who changes a route and immediately tests it
//! would otherwise see the old one and conclude the change had not applied. `BEGIN IMMEDIATE` is what keeps the two
//! processes from corrupting each other in the meantime.
//!
//! # The `--json` contract
//!
//! `--json` output is a versioned API, not a convenience. It is the seam
//! anything built on top of Pigeon consumes, and a process boundary keeps such
//! integrations free of any coupling to the database schema.
//!
//! Five rules, and they hold for failures as well as successes:
//!
//! 1. **Exactly one JSON value on stdout.** Every invocation, including one
//!    that fails. A consumer parses stdout unconditionally and never has to
//!    decide whether there is anything there.
//! 2. **Nothing else on stdout.** Human notes, warnings and progress go to
//!    stderr, where they cannot corrupt the parse.
//! 3. **`format_version` on every response.** It starts at 1 and moves only
//!    when the output contract changes — never because storage did. See
//!    `M1-SCHEMA.md` S-4.
//! 4. **`error` is always present**, `null` on success and an object with a
//!    stable `code` on failure. The discriminator is a field rather than the
//!    exit code, so a consumer that pipes stdout does not need the exit status
//!    to interpret it.
//! 5. **Deterministic ordering.** Arrays are sorted by a stated key; object
//!    keys are emitted in sorted order. Two runs against the same database
//!    produce byte-identical output.
//!
//! ## `null` versus omitted
//!
//! A field that a command can produce is **always present**. `null` means the
//! field applies and has no value — a domain with no default destination, a
//! route that matched no rule.
//!
//! A **missing key** therefore means only one thing: the build that produced
//! this output did not have that field. That is what makes `format_version`
//! useful rather than decorative — without the rule, a consumer cannot tell an
//! absent value from an absent feature.
//!
//! Empty collections are `[]`, never `null`.
//!
//! `--quiet` prints nothing on success and relies on the exit code, which is
//! also stable — see `docs/CLI.md`.

mod check;
mod import;
mod srs;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pigeon_db::repo::{self, Address, AliasKind};

/// Exit codes, stable across releases so scripts can branch on them.
/// See `docs/CLI.md`.
mod exit {
    use std::process::ExitCode;
    pub const OK: u8 = 0;
    /// Command or configuration error.
    pub const USAGE: u8 = 1;
    /// Database failure.
    pub const DATABASE: u8 = 4;
    /// A check ran and the answer was no. Distinct from `USAGE` so a monitoring
    /// system can tell "this domain cannot carry mail" from "you typed the
    /// command wrong".
    pub const FAILED: u8 = 3;

    pub fn code(n: u8) -> ExitCode {
        ExitCode::from(n)
    }
}

#[derive(Parser)]
#[command(
    name = "pigeon",
    about = "Self-hosted email forwarding.",
    long_about = None,
    disable_help_subcommand = true
)]
struct Cli {
    /// Path to pigeon.toml.
    #[arg(long, global = true, env = "PIGEON_CONFIG")]
    config: Option<PathBuf>,

    /// Act on this database directly, bypassing the configuration file.
    #[arg(long, global = true, env = "PIGEON_DB")]
    db: Option<PathBuf>,

    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,

    /// Show what would change, then stop.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add and configure a domain.
    Domain {
        #[command(subcommand)]
        verb: Option<DomainVerb>,
    },
    /// Act on every domain at once.
    Domains {
        #[command(subcommand)]
        verb: Option<DomainsVerb>,
    },
    /// Forward an address to a mailbox.
    Alias {
        #[command(subcommand)]
        verb: Option<AliasVerb>,
    },
    /// Forward everything unmatched.
    Catchall {
        #[command(subcommand)]
        verb: Option<CatchallVerb>,
    },
    /// Where your mail lands, across all domains.
    Destination {
        #[command(subcommand)]
        verb: Option<DestinationVerb>,
    },
    /// Bulk import from a file.
    Import {
        #[command(subcommand)]
        verb: Option<ImportVerb>,
    },
    /// Trace where an address would go.
    Route {
        #[command(subcommand)]
        verb: Option<RouteVerb>,
    },
    /// Operator notifications.
    Alerts {
        #[command(subcommand)]
        verb: Option<AlertsVerb>,
    },
    /// The SRS key ring that signs return paths.
    Srs {
        #[command(subcommand)]
        verb: Option<SrsVerb>,
    },
}

#[derive(Subcommand)]
enum AlertsVerb {
    /// Send one alert to the configured operator address.
    ///
    /// The channel that reports failures can fail silently — email about email
    /// infrastructure shares a failure domain with the thing it monitors — so
    /// the only way to know it works is to use it.
    Test,
}

#[derive(Subcommand)]
enum SrsVerb {
    /// Show the ring: which key signs, which still verify, and when each may
    /// be deleted.
    Keys,
    /// Add a new signing key, keeping the old ones for verification.
    ///
    /// Never deletes. An SRS address issued before the rotation stays valid
    /// until its window expires, and a bounce is often the last thing to
    /// arrive — so the key that signed it has to outlive the mail, and only an
    /// operator can know that it has.
    Rotate,
}

#[derive(Subcommand)]
enum DomainVerb {
    /// Add a domain.
    Add {
        domain: String,
        /// Where this domain's mail goes by default; aliases inherit it.
        #[arg(long)]
        to: Option<String>,
    },
    /// Delete a domain and everything under it.
    Remove {
        domain: String,
        #[arg(long)]
        yes: bool,
    },
    /// Status, destination and alias count.
    Show { domain: String },
    /// Compare this domain's published DNS with what this host needs.
    Check { domain: String },
    /// Add an Ed25519 signing key alongside the RSA one.
    ///
    /// Additional, never instead: Ed25519 support among receivers is uneven,
    /// and a message signed only with a key the receiver cannot verify has no
    /// usable signature at all.
    Ed25519 { domain: String },
    /// Set where this domain's mail goes by default.
    Forward { domain: String, address: String },
    /// Allow this domain to receive mail.
    Enable { domain: String },
    /// Stop this domain receiving mail.
    Disable { domain: String },
}

#[derive(Subcommand)]
enum DomainsVerb {
    /// Every domain, with its status.
    List,
    /// Check every domain's DNS at once.
    Check,
}

#[derive(Subcommand)]
enum AliasVerb {
    /// Forwarding rules on a domain.
    List { domain: String },
    /// Add one or more aliases.
    Add {
        domain: String,
        /// Comma-separated.
        names: String,
        /// Comma-separated. Omit to inherit the domain default.
        #[arg(long)]
        to: Option<String>,
        /// Refuse this address instead of forwarding it.
        #[arg(long)]
        reject: bool,
    },
    /// Remove one or more aliases.
    Remove {
        domain: String,
        names: Option<String>,
        /// Remove every alias on the domain.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum CatchallVerb {
    /// Forward everything unmatched.
    Add {
        domain: String,
        /// Omit to inherit the domain default.
        #[arg(long)]
        to: Option<String>,
    },
    /// Stop forwarding unmatched addresses.
    Remove { domain: String },
}

#[derive(Subcommand)]
enum DestinationVerb {
    /// Every mailbox, and how much routes to it.
    List,
    /// Repoint every use of one mailbox at another.
    Replace {
        old: String,
        new: String,
        /// Narrow to one domain.
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ImportVerb {
    /// Import aliases from a CSV file.
    Csv {
        file: PathBuf,
        /// Keep existing routing; a differing alias is a conflict.
        #[arg(long, conflicts_with = "replace")]
        merge: bool,
        /// Remove aliases and the catch-all on the imported domains first.
        /// The domain default is preserved.
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RouteVerb {
    /// Trace an inbound address.
    Inbound { address: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => exit::code(code),
        Err(e) => {
            // Under `--json` the failure is still exactly one JSON value on
            // stdout. A consumer parses stdout unconditionally and branches on
            // `error`, rather than having to notice that this particular run
            // wrote nothing there.
            if cli.json {
                json::fail(&error_code(&e), &e.to_string());
            } else {
                eprintln!("Error: {e}");
            }
            exit::code(classify(&e))
        }
    }
}

/// A stable machine-readable name for a failure.
///
/// Part of the `--json` contract: these strings do not change without
/// `format_version` moving. The human `message` beside them is free to be
/// rewritten, which is the point of having both.
fn error_code(e: &anyhow::Error) -> String {
    use pigeon_db::DbError;
    use pigeon_route::MutationError;

    if let Some(db) = e.downcast_ref::<DbError>() {
        return db_code(db).to_string();
    }
    if let Some(m) = e.downcast_ref::<MutationError>() {
        return match m {
            MutationError::Invalid(_) => "invalid_configuration",
            MutationError::Db(db) => db_code(db),
            MutationError::Load(_) => "unreadable_configuration",
            MutationError::Sqlite(_) => "database",
        }
        .to_string();
    }
    if e.downcast_ref::<pigeon_auth::DkimError>().is_some() {
        return "dkim".to_string();
    }
    if e.downcast_ref::<pigeon_config::ConfigError>().is_some() {
        return "configuration".to_string();
    }
    "usage".to_string()
}

fn db_code(e: &pigeon_db::DbError) -> &'static str {
    use pigeon_db::DbError as E;
    match e {
        E::NoSuchDomain(_) => "no_such_domain",
        E::DomainExists(_) => "domain_exists",
        E::AliasExists { .. } => "alias_exists",
        E::RejectWithDestinations(_) => "reject_with_destinations",
        E::CatchAllNeedsDestination(_) => "catchall_needs_destination",
        E::BadAddress(_) => "invalid_address",
        E::DatabaseFromTheFuture { .. } => "schema_too_new",
        _ => "database",
    }
}

/// Map a failure onto the documented exit codes.
fn classify(e: &anyhow::Error) -> u8 {
    if e.downcast_ref::<pigeon_db::DbError>().is_some()
        || e.downcast_ref::<pigeon_route::MutationError>().is_some()
    {
        return exit::DATABASE;
    }
    exit::USAGE
}

/// Where the database lives.
///
/// `--db` wins, then the configuration file, then the documented default. The
/// direct path exists because a control-plane command should not require a
/// fully validated daemon configuration — the database is the only thing it
/// touches.
fn database_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    if let Some(p) = &cli.db {
        return Ok(p.clone());
    }
    if let Some(p) = &cli.config {
        let config = pigeon_config::Config::load(p)?;
        return Ok(config.database);
    }
    Ok(PathBuf::from("/var/lib/pigeon/pigeon.db"))
}

fn open_read(cli: &Cli) -> anyhow::Result<rusqlite::Connection> {
    let path = database_path(cli)?;
    if !path.exists() {
        anyhow::bail!(
            "no database at {}\n\n  Start the daemon once to create it, or point at \
             another with --db.",
            path.display()
        );
    }
    Ok(pigeon_db::open_read_only(&path)?)
}

fn open_write(cli: &Cli) -> anyhow::Result<rusqlite::Connection> {
    let path = database_path(cli)?;
    if !path.exists() {
        anyhow::bail!(
            "no database at {}\n\n  Start the daemon once to create it, or point at \
             another with --db.",
            path.display()
        );
    }
    let conn = pigeon_db::open(&path)?;
    let version = pigeon_db::schema_version(&conn)?;
    let known = pigeon_db::MIGRATIONS.last().map(|m| m.version).unwrap_or(0);
    if version != known {
        // Only the daemon migrates (`M1-SCHEMA.md` I7). A CLI meeting a schema
        // it does not know must not write against it.
        anyhow::bail!(
            "database is at schema version {version}, this build knows {known}\n\n  \
             Start pigeond to migrate it. Only the daemon migrates."
        );
    }
    Ok(conn)
}

/// Apply a mutation under the contract, or preview it.
///
/// The router here is local and thrown away: nothing in this process serves
/// mail. It exists because `mutate` publishes as its last step, and a mutation
/// path that skipped publication would be a second, subtly different contract.
/// What the daemon needs is the committed rows, which it reads at startup.
fn apply<T>(
    cli: &Cli,
    conn: &mut rusqlite::Connection,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, pigeon_db::DbError>,
) -> anyhow::Result<pigeon_route::Outcome<T>> {
    if cli.dry_run {
        return Ok(pigeon_route::preview(conn, f)?);
    }
    let router = pigeon_route::Router::default();
    Ok(pigeon_route::mutate(conn, &router, f)?)
}

/// Say what the change means for a daemon that is already running.
///
/// Two things are true and the note has to carry both. The daemon *does* pick
/// the change up on its own now, and it does not route mail from that table
/// until Milestone 3. Claiming only the first would tell an operator their
/// forwarding had changed.
///
/// It states the *cadence*, not a deadline. `POLL` is the sleep between
/// iterations, so the interval from commit to published is that sleep plus the
/// rebuild, and longer when a commit lands during snapshot construction and is
/// caught only by a later poll. "Within one second" would be a latency
/// guarantee the detector does not offer.
///
/// Backoff is *not* one of those cases, though it looks like one. The throttle
/// is keyed on the version that failed, so a commit fixing an invalid
/// configuration moves `data_version` past it and rebuilds on the next poll.
/// Backoff delays retrying a failure, never the fix for it.
///
/// The interval is read from the detector rather than written here, so change
/// the poll and this sentence changes with it. A hardcoded number is how a note
/// becomes a lie one constant at a time.
fn note_reload(cli: &Cli) {
    if !cli.dry_run {
        note(
            cli,
            &format!(
                "\nA running pigeond polls for routing changes every {:?}; it does not \
                 route mail from that table until Milestone 3.",
                pigeon_route::reload::POLL
            ),
        );
    }
}

fn addresses(raw: &str) -> anyhow::Result<Vec<Address>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Address::parse(s).map_err(Into::into))
        .collect()
}

fn names(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The human form of each report.
///
/// Under `--json` these go to stderr *as well as* appearing as structured
/// `reports` in the response. Dropping them there would hide a redundant alias
/// from exactly the operator most likely to be running a script over it.
fn print_reports(cli: &Cli, reports: &[pigeon_route::Report]) {
    for r in reports {
        note(cli, &format!("\nNote: {r}"));
    }
}

fn run(cli: &Cli) -> anyhow::Result<u8> {
    let Some(command) = &cli.command else {
        // A bare `pigeon` is someone asking what they can do, not a usage error.
        print_overview();
        return Ok(exit::OK);
    };

    match command {
        Command::Domain { verb } => match verb {
            None => {
                print_help("domain");
                Ok(exit::OK)
            }
            Some(v) => domain(cli, v),
        },
        Command::Domains { verb } => match verb {
            None | Some(DomainsVerb::List) => domains_list(cli),
            Some(DomainsVerb::Check) => {
                let conn = open_read(cli)?;
                let config = config_for_checks(cli)?;
                check::all(&conn, &config, cli.json)
            }
        },
        Command::Alias { verb } => match verb {
            None => {
                print_help("alias");
                Ok(exit::OK)
            }
            Some(v) => alias(cli, v),
        },
        Command::Catchall { verb } => match verb {
            None => {
                print_help("catchall");
                Ok(exit::OK)
            }
            Some(v) => catchall(cli, v),
        },
        Command::Destination { verb } => match verb {
            None | Some(DestinationVerb::List) => destination_list(cli),
            Some(v) => destination(cli, v),
        },
        Command::Import { verb } => match verb {
            None => {
                print_help("import");
                Ok(exit::OK)
            }
            Some(v) => import_cmd(cli, v),
        },
        Command::Alerts { verb } => match verb {
            None => {
                print_help("alerts");
                Ok(exit::OK)
            }
            Some(AlertsVerb::Test) => alerts_test(cli),
        },
        Command::Srs { verb } => {
            let path = srs_ring_path(cli)?;
            match verb {
                None => {
                    print_help("srs");
                    Ok(exit::OK)
                }
                Some(SrsVerb::Keys) => srs::keys(&path, cli.json),
                Some(SrsVerb::Rotate) => srs::rotate(&path, cli.json),
            }
        }
        Command::Route { verb } => match verb {
            None => {
                print_help("route");
                Ok(exit::OK)
            }
            Some(RouteVerb::Inbound { address }) => route_inbound(cli, address),
        },
    }
}

// ------------------------------------------------------------------ domains

fn domain(cli: &Cli, verb: &DomainVerb) -> anyhow::Result<u8> {
    match verb {
        DomainVerb::Add { domain, to } => {
            let mut conn = open_write(cli)?;
            let default = to.as_deref().map(Address::parse).transpose()?;
            let keys_root = keys_root(cli)?;
            let name = domain.to_ascii_lowercase();

            // Generated before the transaction opens: it takes a second or two,
            // and holding the write lock through that would block every other
            // command for no reason.
            let pair = pigeon_auth::KeyPair::generate(pigeon_auth::dkim::DEFAULT_BITS)?;
            let selector = pigeon_auth::dkim::DEFAULT_SELECTOR;

            // A name no earlier key can already hold.
            //
            // `{domain}.key` collided deterministically: `domain remove` keeps
            // the key file on purpose — it is the one piece of state no backup
            // of the database restores — so a later `domain add` for the same
            // name met a file `create_new` refused. With the write after the
            // commit, that left the domain committed against a public key whose
            // private half was the *previous* key, and the daemon then refused
            // to start. Reproduced before fixing.
            let key_file = format!("{name}.{selector}.{}.key", nonce());
            let key_path = keys_root.join(&key_file);

            // Written and fsynced *before* the transaction, so the row can only
            // ever name a key that is already durable. The reverse order — the
            // one this replaces — turns any write or fsync failure into a
            // committed domain with no usable key.
            if !cli.dry_run {
                write_private_key(&key_path, pair.private_pem())?;
            }

            let outcome = apply(cli, &mut conn, |tx| {
                repo::add_domain(tx, domain, default.as_ref())?;
                repo::add_dkim_key(tx, domain, selector, pair.public_base64(), &key_file)
                    .map(|_| ())
            });

            // A key file whose transaction did not commit belongs to no domain
            // and can never be referenced, since the next attempt generates a
            // new name. Removing it here keeps a failed command from leaving
            // private key material behind.
            let outcome = match outcome {
                Ok(o) => o,
                Err(e) => {
                    if !cli.dry_run {
                        let _ = std::fs::remove_file(&key_path);
                    }
                    return Err(e);
                }
            };

            if cli.json {
                json::ok(serde_json::json!({
                    "domain": name,
                    "status": "new",
                    "default_destination": to,
                    "dkim": {
                        "selector": selector,
                        "record_name": pigeon_auth::dkim::record_name(selector, &name),
                        "record_value": pair.txt_record(),
                        "private_key": key_path.display().to_string(),
                    },
                }));
            } else {
                println!("Adding {name}...\n");
                println!("  Domain created");
                println!("  DKIM key generated\n");
                match to {
                    Some(t) => println!("Mail forwards to {t} unless an alias says otherwise.\n"),
                    None => println!(
                        "It has no default destination yet, so aliases will each need --to.\n  \
                         Set one with:  pigeon domain forward {name} you@example.net\n"
                    ),
                }

                println!("Publish this record:\n");
                println!("  Type:  TXT");
                println!(
                    "  Name:  {}",
                    pigeon_auth::dkim::record_name(selector, &name)
                );
                println!("  Value: {}\n", pair.txt_record());

                println!(
                    "The private key is at {}. It never leaves this host and cannot be\n\
                     regenerated — losing it means publishing a new record by hand. Back it up.\n",
                    key_path.display()
                );

                println!(
                    "{name} will not carry mail until DNS validation moves it to ACTIVE, \
                     which is Milestone 5."
                );
            }
            print_reports(cli, &outcome.reports);
            note_reload(cli);
            Ok(exit::OK)
        }

        DomainVerb::Remove { domain, yes } => {
            let mut conn = open_write(cli)?;
            let impact = repo::removal_impact(&conn, domain)?;

            if !yes && !cli.dry_run {
                // A confirmation prompt has no JSON form: there is nothing for a
                // consumer to do with it except pass `--yes`, and printing a
                // "please confirm" object would invite a script to treat it as
                // the outcome. So the machine-readable answer is the failure
                // envelope, and the prose goes to stderr.
                if cli.json {
                    json::fail(
                        "confirmation_required",
                        &format!(
                            "removing {} deletes {} aliases and orphans {} DKIM key(s); \
                             re-run with --yes",
                            domain.to_ascii_lowercase(),
                            impact.aliases,
                            impact.dkim_selectors.len()
                        ),
                    );
                    return Ok(exit::USAGE);
                }
                // The heaviest prompt in Pigeon, because two of these lines are
                // irreversible in ways that are not obvious while typing.
                println!("This permanently deletes:\n");
                println!("  {} aliases", impact.aliases);
                if let Some(c) = &impact.catchall {
                    println!("  catch-all -> {c}");
                }
                if impact.sender_identities > 0 {
                    println!("  {} sender identities", impact.sender_identities);
                }
                for s in &impact.dkim_selectors {
                    println!("  DKIM key   {s}._domainkey.{domain}");
                }
                if !impact.dkim_selectors.is_empty() {
                    println!(
                        "\nThe DKIM key cannot be regenerated. Re-adding {domain} later creates a \
                         new key and requires publishing a new DNS record."
                    );
                }
                println!("\nRe-run with --yes to confirm.");
                return Ok(exit::USAGE);
            }

            apply(cli, &mut conn, |tx| repo::remove_domain(tx, domain))?;
            if !cli.json {
                println!("Removed {}.", domain.to_ascii_lowercase());
                note_reload(cli);
            }
            Ok(exit::OK)
        }

        DomainVerb::Show { domain } => {
            let conn = open_read(cli)?;
            let all = repo::list_domains(&conn)?;
            let Some(d) = all.iter().find(|d| d.name == domain.to_ascii_lowercase()) else {
                return Err(pigeon_db::DbError::NoSuchDomain(domain.clone()).into());
            };
            let aliases = repo::list_aliases(&conn, domain)?;

            if cli.json {
                json::ok(serde_json::json!({
                    "domain": d.name,
                    "status": d.status,
                    "inbound_enabled": d.inbound_enabled,
                    "outbound_enabled": d.outbound_enabled,
                    "default_destination": d.default_destination,
                    "catchall": d.catchall,
                    "aliases": aliases.len(),
                }));
            } else {
                println!("{}\n", d.name);
                println!("  Status     {}", d.status);
                println!(
                    "  Inbound    {}",
                    if d.inbound_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                println!(
                    "  Outbound   {}",
                    if d.outbound_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                println!(
                    "  Default    {}",
                    d.default_destination.as_deref().unwrap_or("(none)")
                );
                println!("  Catch-all  {}", if d.catchall { "on" } else { "off" });
                println!("  Aliases    {}", aliases.len());

                if d.status == "active" && !d.inbound_enabled {
                    println!(
                        "\nIt passes every check and is switched off, so it refuses mail.\n  \
                         pigeon domain enable {}",
                        d.name
                    );
                }
            }
            Ok(exit::OK)
        }

        DomainVerb::Check { domain } => {
            let conn = open_read(cli)?;
            let config = config_for_checks(cli)?;
            check::one(&conn, &config, domain, cli.json)
        }

        DomainVerb::Ed25519 { domain } => {
            let mut conn = open_write(cli)?;
            let keys_root = keys_root(cli)?;
            let name = domain.to_ascii_lowercase();

            let pair = pigeon_auth::dkim::Ed25519Pair::generate()?;
            let selector = "ed25519";
            let key_file = format!("{name}.{selector}.{}.key", nonce());
            let key_path = keys_root.join(&key_file);

            // Written and fsynced before the transaction, like the RSA key: a
            // row may only ever name a key that is already durable.
            if !cli.dry_run {
                write_private_key_bytes(&key_path, pair.pkcs8())?;
            }

            let outcome = apply(cli, &mut conn, |tx| {
                repo::add_ed25519_key(tx, &name, selector, pair.public_base64(), &key_file)
                    .map(|_| ())
            });

            let outcome = match outcome {
                Ok(o) => o,
                Err(e) => {
                    if !cli.dry_run {
                        let _ = std::fs::remove_file(&key_path);
                    }
                    return Err(e);
                }
            };
            let _ = outcome;

            let record_name = pigeon_auth::dkim::record_name(selector, &name);
            if cli.json {
                json::ok(serde_json::json!({
                    "domain": name,
                    "dkim": {
                        "selector": selector,
                        "algorithm": "ed25519",
                        "record_name": record_name,
                        "record_value": pair.txt_record(),
                        "private_key": key_path.display().to_string(),
                    },
                }));
            } else {
                println!("Added an Ed25519 key for {name}.\n");
                println!("Publish this record as well as the RSA one:\n");
                println!("  Type:  TXT");
                println!("  Name:  {record_name}");
                println!("  Value: {}\n", pair.txt_record());
                println!(
                    "Both signatures are added to every forwarded message, and a receiver\n\
                     verifies whichever it understands. Keep the RSA record published."
                );
            }
            Ok(exit::OK)
        }

        DomainVerb::Forward { domain, address } => {
            let mut conn = open_write(cli)?;
            let to = Address::parse(address)?;
            let outcome = apply(cli, &mut conn, |tx| {
                repo::set_default_destination(tx, domain, Some(&to))
            })?;
            let name = domain.to_ascii_lowercase();
            if cli.json {
                json::ok(serde_json::json!({
                    "domain": name,
                    "default_destination": address,
                    "reports": reports_json(&outcome.reports),
                }));
            } else {
                println!("{name} now forwards to {address} by default.");
                println!("  Aliases with their own destination are unchanged.");
            }
            print_reports(cli, &outcome.reports);
            note_reload(cli);
            Ok(exit::OK)
        }

        DomainVerb::Enable { domain } => set_enabled(cli, domain, true),
        DomainVerb::Disable { domain } => set_enabled(cli, domain, false),
    }
}

fn set_enabled(cli: &Cli, domain: &str, on: bool) -> anyhow::Result<u8> {
    let mut conn = open_write(cli)?;
    apply(cli, &mut conn, |tx| {
        repo::set_inbound_enabled(tx, domain, on)
    })?;
    let d = domain.to_ascii_lowercase();
    if cli.json {
        json::ok(serde_json::json!({ "domain": d, "inbound_enabled": on }));
    } else if on {
        println!("{d} will accept mail once DNS validation passes.");
    } else {
        println!("{d} will refuse mail. Its DNS state is unchanged.");
    }
    note_reload(cli);
    Ok(exit::OK)
}

fn domains_list(cli: &Cli) -> anyhow::Result<u8> {
    let conn = open_read(cli)?;
    let domains = repo::list_domains(&conn)?;

    if cli.json {
        let rows: Vec<_> = domains
            .iter()
            .map(|d| {
                serde_json::json!({
                    "domain": d.name,
                    "status": d.status,
                    "inbound_enabled": d.inbound_enabled,
                    "aliases": d.aliases,
                    "catchall": d.catchall,
                    "default_destination": d.default_destination,
                })
            })
            .collect();
        json::ok(serde_json::json!({ "domains": rows }));
        return Ok(exit::OK);
    }

    if domains.is_empty() {
        println!("No domains yet.\n\n  pigeon domain add example.com --to you@example.net");
        return Ok(exit::OK);
    }

    println!(
        "{:<28} {:<12} {:>8}  {:<9} DEFAULT",
        "DOMAIN", "STATUS", "ALIASES", "CATCH-ALL"
    );
    for d in &domains {
        let status = if d.inbound_enabled {
            d.status.clone()
        } else {
            format!("{} (off)", d.status)
        };
        println!(
            "{:<28} {:<12} {:>8}  {:<9} {}",
            d.name,
            status,
            d.aliases,
            if d.catchall { "yes" } else { "no" },
            d.default_destination.as_deref().unwrap_or("-")
        );
    }
    Ok(exit::OK)
}

// ------------------------------------------------------------------ aliases

fn alias(cli: &Cli, verb: &AliasVerb) -> anyhow::Result<u8> {
    match verb {
        AliasVerb::List { domain } => {
            let conn = open_read(cli)?;
            let aliases = repo::list_aliases(&conn, domain)?;
            let summary = repo::list_domains(&conn)?;
            let d = summary
                .iter()
                .find(|d| d.name == domain.to_ascii_lowercase());
            let default = d.and_then(|d| d.default_destination.clone());

            if cli.json {
                let rows: Vec<_> = aliases
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "pattern": a.pattern,
                            "reject": a.reject,
                            "inherits": !a.reject && a.destinations.is_empty(),
                            "destinations": a.destinations,
                        })
                    })
                    .collect();
                json::ok(serde_json::json!({
                    "domain": domain.to_ascii_lowercase(),
                    "aliases": rows,
                }));
                return Ok(exit::OK);
            }

            if aliases.is_empty() {
                println!("No aliases on {}.", domain.to_ascii_lowercase());
                return Ok(exit::OK);
            }

            println!("{:<24} DESTINATION", "ALIAS");
            for a in &aliases {
                let to = if a.reject {
                    "—                        REJECT".to_string()
                } else if a.destinations.is_empty() {
                    match &default {
                        Some(d) => format!("{d}  (domain default)"),
                        // Refused by the snapshot, so it cannot be live — but it
                        // can be seen through a read command on a database the
                        // daemon has not accepted.
                        None => "(inherits, and the domain has no default)".to_string(),
                    }
                } else {
                    a.destinations.join(", ")
                };
                println!("{:<24} {}", a.pattern, to);
            }
            Ok(exit::OK)
        }

        AliasVerb::Add {
            domain,
            names: raw,
            to,
            reject,
        } => {
            let mut conn = open_write(cli)?;
            let patterns = names(raw);
            if patterns.is_empty() {
                anyhow::bail!("no alias names given");
            }
            let destinations = match to {
                Some(t) => addresses(t)?,
                None => Vec::new(),
            };
            if *reject && !destinations.is_empty() {
                anyhow::bail!(
                    "--reject and --to cannot be used together: a reject rule refuses an address rather than forwarding it"
                );
            }
            let kind = if *reject {
                AliasKind::Reject
            } else {
                AliasKind::Forward
            };

            let outcome = apply(cli, &mut conn, |tx| {
                for p in &patterns {
                    repo::add_alias(tx, domain, p, kind, &destinations)?;
                }
                Ok(())
            })?;

            if cli.json {
                json::ok(serde_json::json!({
                    "domain": domain.to_ascii_lowercase(),
                    "added": patterns,
                    "reject": reject,
                    // Always an array, never null: an empty one means the alias
                    // inherits, which `inherits` states outright so a consumer
                    // does not have to infer it from a length.
                    "destinations": destinations
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    "inherits": destinations.is_empty() && !reject,
                    "reports": reports_json(&outcome.reports),
                }));
            } else {
                let d = domain.to_ascii_lowercase();
                println!("Added to {d}:\n");
                for p in &patterns {
                    let target = if *reject {
                        "REJECT".to_string()
                    } else if destinations.is_empty() {
                        "domain default".to_string()
                    } else {
                        destinations
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    println!("  {}@{d}  ->  {target}", p.to_ascii_lowercase());
                }
            }
            print_reports(cli, &outcome.reports);
            note_reload(cli);
            Ok(exit::OK)
        }

        AliasVerb::Remove {
            domain,
            names: raw,
            all,
            yes,
        } => {
            let mut conn = open_write(cli)?;

            if *all {
                let existing = repo::list_aliases(&conn, domain)?;
                if !yes && !cli.dry_run {
                    if cli.json {
                        json::fail(
                            "confirmation_required",
                            &format!(
                                "removing all {} aliases on {}; re-run with --yes",
                                existing.len(),
                                domain.to_ascii_lowercase()
                            ),
                        );
                    } else {
                        println!(
                            "This removes all {} aliases on {}.\n\nRe-run with --yes to confirm.",
                            existing.len(),
                            domain.to_ascii_lowercase()
                        );
                    }
                    return Ok(exit::USAGE);
                }
                let outcome = apply(cli, &mut conn, |tx| repo::remove_all_aliases(tx, domain))?;
                if cli.json {
                    json::ok(serde_json::json!({
                        "domain": domain.to_ascii_lowercase(),
                        "removed": outcome.value,
                        // `null`, not omitted: `--all` names no patterns, and a
                        // consumer must be able to tell "no count applies" from
                        // "this build does not report one".
                        "requested": serde_json::Value::Null,
                    }));
                } else {
                    println!("Removed {} aliases.", outcome.value);
                }
                note_reload(cli);
                return Ok(exit::OK);
            }

            let Some(raw) = raw else {
                anyhow::bail!(
                    "name the aliases to remove, or pass --all\n\n  \
                     --all is a flag rather than '*' or the word 'all' because both are \
                     real alias names."
                );
            };
            let patterns = names(raw);
            let outcome = apply(cli, &mut conn, |tx| {
                let mut removed = 0;
                for p in &patterns {
                    if repo::remove_alias(tx, domain, p)? {
                        removed += 1;
                    }
                }
                Ok(removed)
            })?;

            if cli.json {
                json::ok(serde_json::json!({
                    "domain": domain.to_ascii_lowercase(),
                    "removed": outcome.value,
                    "requested": patterns.len(),
                }));
            } else {
                println!("Removed {} of {}.", outcome.value, patterns.len());
                if outcome.value < patterns.len() {
                    println!("  The rest did not exist.");
                }
            }
            note_reload(cli);
            Ok(exit::OK)
        }
    }
}

// --------------------------------------------------------------- catch-all

fn catchall(cli: &Cli, verb: &CatchallVerb) -> anyhow::Result<u8> {
    match verb {
        CatchallVerb::Add { domain, to } => {
            let mut conn = open_write(cli)?;
            let dest = to.as_deref().map(Address::parse).transpose()?;
            let outcome = apply(cli, &mut conn, |tx| {
                repo::set_catchall(tx, domain, dest.as_ref())
            })?;

            let d = domain.to_ascii_lowercase();
            if cli.json {
                json::ok(serde_json::json!({
                    "domain": d,
                    "catchall_enabled": true,
                    // `null` means it inherits the domain default, which is a
                    // real state and not a missing one.
                    "destination": to,
                    "reports": reports_json(&outcome.reports),
                }));
            } else {
                match to {
                    Some(t) => println!("Catch-all enabled on {d}: -> {t}"),
                    None => println!("Catch-all enabled on {d}, forwarding to the domain default."),
                }
            }
            note(
                cli,
                &format!(
                    "\nEvery address on {d} is now accepted at RCPT TO, so recipient rejection \
                     no longer applies and dictionary attacks get 250 rather than 550."
                ),
            );
            print_reports(cli, &outcome.reports);
            note_reload(cli);
            Ok(exit::OK)
        }
        CatchallVerb::Remove { domain } => {
            let mut conn = open_write(cli)?;
            apply(cli, &mut conn, |tx| repo::clear_catchall(tx, domain))?;
            let d = domain.to_ascii_lowercase();
            if cli.json {
                json::ok(serde_json::json!({
                    "domain": d,
                    "catchall_enabled": false,
                    "destination": serde_json::Value::Null,
                }));
            } else {
                println!("Catch-all removed from {d}. Unmatched addresses are refused again.");
            }
            note_reload(cli);
            Ok(exit::OK)
        }
    }
}

// ------------------------------------------------------------ destinations

fn destination_list(cli: &Cli) -> anyhow::Result<u8> {
    let conn = open_read(cli)?;
    let all = repo::list_destinations(&conn)?;

    if cli.json {
        let rows: Vec<_> = all
            .iter()
            .map(|d| {
                serde_json::json!({
                    "destination": d.address.to_string(),
                    "aliases": d.aliases,
                    "domains": d.domains,
                    "default_for": d.default_for,
                })
            })
            .collect();
        json::ok(serde_json::json!({ "destinations": rows }));
        return Ok(exit::OK);
    }

    if all.is_empty() {
        println!("Nothing forwards anywhere yet.");
        return Ok(exit::OK);
    }

    println!(
        "{:<32} {:>8} {:>9} {:>12}",
        "DESTINATION", "ALIASES", "DOMAINS", "DEFAULT FOR"
    );
    for d in &all {
        println!(
            "{:<32} {:>8} {:>9} {:>12}",
            d.address.to_string(),
            d.aliases,
            d.domains,
            if d.default_for == 0 {
                "-".to_string()
            } else {
                d.default_for.to_string()
            }
        );
    }
    Ok(exit::OK)
}

fn destination(cli: &Cli, verb: &DestinationVerb) -> anyhow::Result<u8> {
    let DestinationVerb::Replace {
        old,
        new,
        domain,
        yes,
    } = verb
    else {
        return destination_list(cli);
    };

    let mut conn = open_write(cli)?;
    let old_addr = Address::parse(old)?;
    let new_addr = Address::parse(new)?;

    // Preview first, always. This runs the real mutation and rolls it back, so
    // the count is of what would actually move rather than of a model of it.
    let preview = pigeon_route::preview(&mut conn, |tx| {
        repo::replace_destination(tx, &old_addr, &new_addr, domain.as_deref())
    })?;

    if preview.value == 0 {
        if cli.json {
            json::ok(serde_json::json!({
                "old": old, "new": new, "domain": domain, "moved": 0, "applied": false,
            }));
        } else {
            println!("Nothing forwards to {old}.");
        }
        return Ok(exit::OK);
    }

    if !yes && !cli.dry_run {
        if cli.json {
            // The same shape as every other refused-pending-confirmation
            // command. `--dry-run` is how a consumer gets the count as data;
            // running without `--yes` is a refusal, and a refusal is an error
            // envelope so a script cannot mistake it for the outcome.
            json::fail(
                "confirmation_required",
                &format!(
                    "this repoints {} reference(s) from {old} to {new}; re-run with --yes",
                    preview.value
                ),
            );
        } else {
            println!(
                "This repoints {} reference(s) from {old} to {new}{}.\n\nRe-run with --yes to confirm.",
                preview.value,
                match domain {
                    Some(d) => format!(" on {d}"),
                    None => String::new(),
                }
            );
        }
        return Ok(exit::USAGE);
    }
    if cli.dry_run {
        if cli.json {
            json::ok(serde_json::json!({
                "old": old, "new": new, "domain": domain,
                "moved": preview.value, "applied": false,
            }));
        } else {
            println!("Would repoint {} reference(s).", preview.value);
        }
        return Ok(exit::OK);
    }

    let outcome = apply(cli, &mut conn, |tx| {
        repo::replace_destination(tx, &old_addr, &new_addr, domain.as_deref())
    })?;
    if cli.json {
        json::ok(serde_json::json!({
            "old": old, "new": new, "domain": domain,
            "moved": outcome.value, "applied": true,
        }));
    } else {
        println!("Repointed {} reference(s).", outcome.value);
    }
    note_reload(cli);
    Ok(exit::OK)
}

// ------------------------------------------------------------------- route

fn route_inbound(cli: &Cli, address: &str) -> anyhow::Result<u8> {
    use pigeon_route::{Decision, Snapshot};

    let conn = open_read(cli)?;
    let built = Snapshot::build(pigeon_route::load(&conn)?)
        .map_err(pigeon_route::MutationError::Invalid)?;
    let parsed = pigeon_types::Address::parse(address)
        .map_err(|e| anyhow::anyhow!("{address:?} is not a valid address: {e}"))?;

    // The same function the daemon calls. A second implementation here is how a
    // prediction and the behaviour it predicts drift apart.
    let decision = built.snapshot.resolve(&parsed);

    if cli.json {
        let (result, tier, matched, destinations) = match &decision {
            Decision::Forward {
                tier,
                matched,
                destinations,
            } => (
                "accept",
                Some(format!("{tier:?}")),
                Some(matched.to_string()),
                destinations.iter().map(ToString::to_string).collect(),
            ),
            Decision::Reject { tier, matched } => (
                "reject",
                Some(format!("{tier:?}")),
                Some(matched.to_string()),
                Vec::new(),
            ),
            Decision::NoRoute => ("reject", None, None, Vec::new()),
            Decision::UnknownDomain => ("unknown_domain", None, None, Vec::new()),
            Decision::DomainNotAccepting => ("domain_not_accepting", None, None, Vec::new()),
        };
        json::ok(serde_json::json!({
            "address": address,
            "result": result,
            "tier": tier,
            "matched": matched,
            "destinations": destinations,
        }));
        eprintln!("{ROUTE_CAVEAT}");
        return Ok(if decision.accepts() {
            exit::OK
        } else {
            exit::USAGE
        });
    }

    println!("{address}");
    println!("      |");
    println!("{}", parsed.domain());
    match &decision {
        Decision::Forward {
            tier,
            matched,
            destinations,
        } => {
            println!("      |");
            println!("{}", describe(*tier, matched));
            println!("      |");
            for d in *destinations {
                println!("{d}");
            }
            println!("\nACCEPT");
        }
        Decision::Reject { tier, matched } => {
            println!("      |");
            println!("{}", describe(*tier, matched));
            println!("\nREJECT\n\nReason:\n  the rule refuses this address");
        }
        Decision::NoRoute => {
            println!("\nREJECT\n\nReason:\n  no alias matched\n  catch-all disabled");
        }
        Decision::UnknownDomain => {
            println!(
                "\nREJECT\n\nReason:\n  this Pigeon does not carry {}",
                parsed.domain()
            );
        }
        Decision::DomainNotAccepting => {
            println!(
                "\nREJECT\n\nReason:\n  {} is not accepting mail: it has not passed DNS \
                 validation, or it is switched off",
                parsed.domain()
            );
        }
    }

    // The M1 exit criterion is that this exactly predicts runtime routing, and
    // it does not yet, because the daemon does not route from this table. Said
    // here rather than only in a document, because this is where somebody
    // would rely on it.
    eprintln!("{ROUTE_CAVEAT}");

    Ok(if decision.accepts() {
        exit::OK
    } else {
        exit::USAGE
    })
}

fn describe(tier: pigeon_route::Tier, matched: &str) -> String {
    use pigeon_route::Tier;
    match tier {
        Tier::ExactFull | Tier::ExactBase => format!("alias: {matched}"),
        Tier::Wildcard => format!("wildcard: {matched}"),
        Tier::CatchAll => "catch-all".to_string(),
    }
}

// -------------------------------------------------------------------- help

fn print_overview() {
    println!(
        r#"Pigeon — self-hosted email forwarding.

USAGE
  pigeon <command> [options]

SETUP
  domain      add and configure a domain
  alias       forward an address to a mailbox
  catchall    forward everything else
  destination where your mail lands, across all domains

INSPECT
  route       trace where an address would go
  domains     act on every domain at once

  pigeon <command> --help   for detail on any of these

Getting started:

  pigeon domain add example.com --to you@example.net
  pigeon alias add example.com hello,hi,support
  pigeon route inbound hello@example.com"#
    );
}

fn print_help(noun: &str) {
    match noun {
        "alerts" => println!(
            r#"Operator notifications.

USAGE
  pigeon alerts <verb>

VERBS
  test       send one alert to the configured operator address

The channel that reports failures can fail silently: email about email
infrastructure shares a failure domain with the thing it monitors, so the
only way to know it works is to use it.

EXAMPLES
  pigeon --config /etc/pigeon/pigeon.toml alerts test"#
        ),
        "domain" => println!(
            r#"Add and configure a domain.

USAGE
  pigeon domain <verb> <domain> [arguments]

VERBS
  add        add a domain
  remove     delete a domain and everything under it
  show       status, destination and alias count
  check      compare published DNS with what this host needs
  forward    set where this domain's mail goes by default
  enable     allow this domain to receive mail
  disable    stop this domain receiving mail

EXAMPLES
  pigeon domain add example.com --to me@example.net
  pigeon domain show example.com
  pigeon domain forward example.com new@example.net
  pigeon domain disable example.com

SEE ALSO
  pigeon domains     act on every domain
  pigeon alias       forwarding rules for a domain"#
        ),
        "alias" => println!(
            r#"Forward an address to a mailbox.

USAGE
  pigeon alias <verb> <domain> [names] [options]

VERBS
  list       forwarding rules on a domain
  add        add one or more aliases
  remove     remove one or more aliases

Names are comma-separated, so several aliases are one command. Omit --to
and the alias inherits the domain default, which is what makes changing
that default move all of them at once.

Patterns take at most one '*', and the most specific rule wins:

  exact alias  ->  wildcard  ->  catch-all  ->  reject unknown

EXAMPLES
  pigeon alias add example.com hello,hi,support
  pigeon alias add example.com billing --to finance@example.net
  pigeon alias add example.com 'shop-*'
  pigeon alias add example.com postmaster-old --reject
  pigeon alias remove example.com hello
  pigeon alias remove example.com --all"#
        ),
        "catchall" => println!(
            r#"Forward everything no alias claims.

USAGE
  pigeon catchall <verb> <domain> [options]

VERBS
  add        forward unmatched addresses
  remove     stop forwarding them

Catch-all is never enabled implicitly. With it on, every address on the
domain is accepted at RCPT TO, so recipient rejection stops applying and
dictionary attacks receive 250 rather than 550.

EXAMPLES
  pigeon catchall add example.com
  pigeon catchall add example.com --to me@example.net
  pigeon catchall remove example.com"#
        ),
        "import" => println!(
            r#"Bulk import from a file.

USAGE
  pigeon import csv <file> [--merge | --replace] [--yes]

The file needs a header row naming `address` and `destination`, and
optionally `kind`. Columns are matched by name, so their order does not
matter. One destination per row; repeating an address fans it out.

  address,destination
  hello@example.com,me@example.net
  support@example.com,me@example.net
  support@example.com,ops@example.net
  shop-*@example.com,shop@example.net
  *@example.com,catchall@example.net

If any imported domain already has aliases or a catch-all, --merge or
--replace is required. An import file says what should exist and nothing
about what should stop existing, so Pigeon will not guess.

--replace removes aliases and catch-alls on the imported domains only, and
keeps their default destinations.

EXAMPLES
  pigeon import csv aliases.csv --dry-run
  pigeon import csv aliases.csv
  pigeon import csv aliases.csv --replace --yes"#
        ),
        "route" => println!(
            r#"Trace where an address would go, without sending anything.

USAGE
  pigeon route inbound <address>

EXAMPLES
  pigeon route inbound hello@example.com
  pigeon route inbound unknown@example.com --json"#
        ),
        _ => print_overview(),
    }
}

/// Where DKIM private keys live.
///
/// Required for `domain add`, which is why this is separate from
/// [`database_path`]: a command that generates a key has to know the one
/// directory it is allowed to put it in, and `--db` alone does not say.
/// Where the SRS ring lives.
///
/// From the configuration when there is one, because that is the file the
/// daemon reads and rotating a different one would look like it worked. There
/// is deliberately no guess: the keys directory can be inferred from the
/// database's location, but a ring is a single file with no conventional name
/// beside it, and rotating the wrong path writes a ring nothing will ever load.
fn srs_ring_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    match &cli.config {
        Some(p) => Ok(pigeon_config::Config::load(p)?.srs_secret_file),
        None => anyhow::bail!(
            "the SRS ring is named in the configuration, so --config is required here\n\n  \
             It is one file with no conventional location beside the database, and\n  \
             rotating the wrong path writes a ring the daemon will never load."
        ),
    }
}

/// The configuration the DNS checks need: this host's name, and nothing else.
///
/// `--config` is not required. The checks compare a domain's published records
/// against this host's name, and an operator running the CLI beside the
/// database has already told us that name — through the configuration file when
/// there is one, and through `--hostname` when there is not. Refusing to check
/// DNS without a full daemon configuration would make the most useful
/// diagnostic the hardest one to run.
fn config_for_checks(cli: &Cli) -> anyhow::Result<pigeon_config::Config> {
    if let Some(p) = &cli.config {
        return Ok(pigeon_config::Config::load(p)?);
    }
    anyhow::bail!(
        "checking DNS needs to know this host's name, which is in the configuration file.\n\n  \
         pigeon --config /etc/pigeon/pigeon.toml domain check <domain>"
    )
}

/// `pigeon alerts test`: send one message down the alert path.
///
/// It uses the real delivery client and the real out-of-band route, because a
/// test that took a different path would be testing a path nobody uses. What it
/// cannot prove is that the message was *read* — only that this host could hand
/// it to the operator's mail server.
fn alerts_test(cli: &Cli) -> anyhow::Result<u8> {
    let config = config_for_checks(cli)?;
    let alerts = &config.alerts;

    if !alerts.enabled {
        anyhow::bail!(
            "alerts are disabled.\n\n  Set alerts.enabled, alerts.identity and alerts.to in {}",
            cli.config
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "the configuration file".into())
        );
    }
    let (Some(identity), Some(to)) = (&alerts.identity, &alerts.to) else {
        anyhow::bail!("alerts.identity and alerts.to must both be set");
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let outcome = runtime.block_on(async {
        // The same relay the daemon's own alerts go through, out of band and
        // never via the routing engine. A test that took a different path would
        // be testing a path nobody uses.
        let resolver = pigeon_dns::SystemResolver::from_system()
            .map_err(|e| format!("cannot build a resolver: {e}"))?;

        let forwarding = pigeon_smtp::relay::Forwarding {
            resolver: std::sync::Arc::new(resolver),
            tls: pigeon_smtp::tls::outbound(),
            // No self-identity: this is a one-off diagnostic and the CLI does
            // not bind the listener, so it cannot say which addresses are the
            // daemon's. The daemon's own alerts get the real one.
            identity: pigeon_smtp::relay::SelfIdentity::default(),
            ehlo_name: config.hostname.clone(),
            limit: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            port: 25,
            budget: std::time::Duration::from_secs(120),
        };

        let body = format!(
            "From: <{identity}>\r\n\
             To: <{to}>\r\n\
             Subject: [pigeon] alert test\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Auto-Submitted: auto-generated\r\n\
             \r\n\
             This is `pigeon alerts test` from {}.\r\n\
             \r\n\
             If it arrived, alerts about gated domains will reach you the same way.\r\n\
             If it did not, the channel is not usable and `pigeon domains check`\r\n\
             remains the source of truth.\r\n",
            config.hostname
        );

        // An empty return path: a bounce for an alert must not produce another
        // alert about the bounce.
        pigeon_smtp::relay::forward(&forwarding, 0, to, "", body.as_bytes())
            .await
            .map_err(|e| e.to_string())
    });

    match outcome {
        Ok(remote) => {
            if cli.json {
                json::ok(serde_json::json!({
                    "sent": true,
                    "to": to,
                    "remote": remote,
                }));
            } else {
                println!("Sent one alert to {to}.\n  {remote}");
                println!(
                    "\nIf it does not arrive, the channel is not usable and \
                     `pigeon domains check` remains the source of truth."
                );
            }
            Ok(exit::OK)
        }
        Err(e) => {
            if cli.json {
                json::fail("alert_failed", &e);
            } else {
                eprintln!("The alert could not be delivered.\n  {e}");
            }
            Ok(exit::FAILED)
        }
    }
}

fn keys_root(cli: &Cli) -> anyhow::Result<PathBuf> {
    if let Some(p) = &cli.config {
        return Ok(pigeon_config::Config::load(p)?.keys);
    }
    if let Some(db) = &cli.db {
        // Beside the database, which is where the documented layout puts it.
        // Guessing is acceptable here only because the alternative is refusing
        // to work at all without a full daemon configuration.
        let guess = db
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("keys");
        if guess.is_dir() {
            return Ok(guess);
        }
        anyhow::bail!(
            "no keys directory at {}\n\n  \
             A DKIM private key needs somewhere to live that the daemon will look in.\n  \
             Create it (mode 0700), or pass --config so the configured path is used.",
            guess.display()
        );
    }
    Ok(PathBuf::from("/var/lib/pigeon/keys"))
}

/// Write a private key so that only this account can read it.
///
/// `create_new`, so an existing key is never overwritten: it is the one piece
/// of state no backup of the database restores, and silently replacing it makes
/// every signature the old key made unverifiable.
///
/// # Every failure after the file exists removes it
///
/// An earlier version returned the write or fsync error and left the partial
/// file behind. Nothing referenced it and nothing would clean it up — import's
/// cleanup only knows about keys whose path it was given, and the path is only
/// recorded once this function *returns*. So a full disk left a truncated
/// private key sitting in the keys directory, under a name a later run would
/// not reuse and no operator would think to look for.
fn write_private_key(path: &std::path::Path, pem: &str) -> anyhow::Result<()> {
    write_private_key_bytes(path, pem.as_bytes())
}

/// The same, for a key that is not text.
///
/// Ed25519 private keys are PKCS#8 DER: `ring` produces DER and `mail-auth`
/// takes it, so wrapping it in PEM would be encoding a thing in order to decode
/// it again.
fn write_private_key_bytes(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut f = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "a DKIM private key already exists at {}\n\n  \
                 It was not replaced. Overwriting it would make every signature the old \n  \
                 key made unverifiable, and no backup of the database restores it.",
                path.display()
            )
        } else {
            anyhow::anyhow!("cannot write {}: {e}", path.display())
        }
    })?;

    // From here the file exists, so every path out of this function has to
    // remove it or leave key material nothing will ever collect.
    let written = (|| -> std::io::Result<()> {
        f.write_all(bytes)?;
        // fsync the file: a key in the page cache and not on disk is a key that
        // a power failure turns into a domain nobody can sign for.
        f.sync_all()
    })();
    drop(f);

    if let Err(e) = written {
        discard_partial_key(path);
        return Err(anyhow::anyhow!("cannot write {}: {e}", path.display()));
    }

    // And the directory, so the *name* is durable too. Without this the file's
    // contents survive a crash and its directory entry may not, which is the
    // same outcome by a different route.
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all())
    {
        discard_partial_key(path);
        return Err(anyhow::anyhow!("cannot flush {}: {e}", dir.display()));
    }
    Ok(())
}

/// Remove a key file this process created and could not finish, and flush the
/// directory so the removal is durable too.
///
/// Best effort by necessity: the reason we are here is that writing failed, and
/// the removal may fail for the same reason. It is not reported separately
/// because the caller is already returning the failure that caused it.
pub(crate) fn discard_partial_key(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
}

/// A short random component for a key filename.
///
/// Not a security boundary — the file is `0600` in a `0700` directory and its
/// name is stored in the database. It exists so that a key file can never
/// collide with one an earlier domain of the same name left behind, which is
/// what made `remove` then `add` break deterministically.
pub(crate) fn nonce() -> String {
    use rsa::rand_core::RngCore;
    let mut bytes = [0u8; 6];
    rsa::rand_core::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `--json` envelope. See the module documentation for the contract.
mod json {
    use serde_json::{Value, json};

    /// Moves only when the *output* contract changes.
    ///
    /// Deliberately not the schema version. A storage migration that adds an
    /// index changes nothing a consumer can observe, and a renamed field
    /// changes everything while possibly needing no migration at all. Tying
    /// them makes every internal change look breaking, and consumers learn to
    /// ignore the signal.
    pub const FORMAT_VERSION: u64 = 1;

    /// Print exactly one JSON value to stdout, and nothing else.
    ///
    /// `error` is inserted as `null` here rather than at each call site, so a
    /// command cannot forget it and produce a response a consumer must special
    /// case.
    pub fn ok(mut payload: Value) {
        if let Some(map) = payload.as_object_mut() {
            map.insert("format_version".into(), json!(FORMAT_VERSION));
            map.insert("error".into(), Value::Null);
        }
        println!("{payload}");
    }

    /// Print the failure envelope. Still exactly one value, still on stdout.
    pub fn fail(code: &str, message: &str) {
        println!(
            "{}",
            json!({
                "format_version": FORMAT_VERSION,
                "error": { "code": code, "message": message },
            })
        );
    }
}

/// A human-facing note.
///
/// stdout in human mode, **stderr** under `--json` — where it is still worth
/// saying and must not land in the parse. Dropping it there would mean the
/// caveat on `route inbound` disappears for exactly the consumers most likely
/// to build something on the answer.
fn note(cli: &Cli, text: &str) {
    if cli.json {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

/// Non-fatal findings, as data rather than prose.
///
/// The human forms go to stderr under `--json`; a consumer that wants to act on
/// a redundant alias should not have to parse an English sentence to find it.
fn reports_json(reports: &[pigeon_route::Report]) -> Vec<serde_json::Value> {
    use pigeon_route::Report;
    reports
        .iter()
        .map(|r| match r {
            Report::RedundantAgainstCatchAll { domain, pattern } => serde_json::json!({
                "kind": "redundant_against_catchall",
                "domain": domain,
                "pattern": pattern,
                "message": r.to_string(),
            }),
            Report::RedundantWildcards { domain, a, b } => serde_json::json!({
                "kind": "redundant_wildcards",
                "domain": domain,
                "patterns": [a, b],
                "message": r.to_string(),
            }),
            Report::ActiveButDisabled { domain } => serde_json::json!({
                "kind": "active_but_disabled",
                "domain": domain,
                "message": r.to_string(),
            }),
        })
        .collect()
}

/// Printed to stderr after every `route inbound`, in both output modes.
///
/// Milestone 1's exit criterion is that this command predicts the control
/// plane, and Milestone 3's is that it predicts the daemon. Until then the
/// difference has to be said where somebody would rely on it — which under
/// `--json` means stderr, not silence.
const ROUTE_CAVEAT: &str = "\nNote: pigeond does not yet route from this table — acceptance still comes \
     from PIGEON_ACCEPT and delivery from PIGEON_FORWARD_TO. This predicts the \
     control plane, not the running daemon — that is Milestone 3. See \
     docs/M1-FINDINGS.md.";

// ------------------------------------------------------------------ import

fn import_cmd(cli: &Cli, verb: &ImportVerb) -> anyhow::Result<u8> {
    use import::plan::{Mode, PrepareError};

    let ImportVerb::Csv {
        file,
        merge,
        replace,
        yes,
    } = verb;

    let mode = match (merge, replace) {
        (true, _) => Some(Mode::Merge),
        (_, true) => Some(Mode::Replace),
        _ => None,
    };

    // Step 1. Nothing is written, and the whole file is read before anything
    // else happens.
    let text = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", file.display()))?;
    let (plan, mut conflicts) = import::parse::parse(&text);

    let mut conn = open_write(cli)?;

    // Step 2 and 3.
    let prepared = match import::plan::prepare(&conn, plan, mode) {
        Ok(p) => p,
        Err(PrepareError::Conflicts(mut c)) => {
            conflicts.append(&mut c);
            return report_conflicts(cli, &conflicts);
        }
        Err(PrepareError::ModeRequired(scoped)) => {
            return mode_required(cli, &scoped);
        }
        Err(PrepareError::Db(e)) => return Err(e.into()),
    };
    if !conflicts.is_empty() {
        return report_conflicts(cli, &conflicts);
    }

    if prepared.mode == Mode::Replace && !yes && !cli.dry_run {
        return replace_needs_confirmation(cli, &prepared);
    }

    if cli.dry_run {
        return dry_run(cli, &mut conn, &prepared);
    }

    // Steps 4 to 6.
    let keys_root = keys_root(cli)?;
    let applied = match import::apply::apply(&mut conn, &keys_root, &prepared, &nonce) {
        Ok(a) => a,
        // Conflicts keep their own path so a real-run failure has the same
        // shape as a preparation failure. Flattening them into `anyhow`
        // produced a generic `usage` code and no `conflicts` array — for
        // the snapshot failure, which is the most interesting kind and the
        // one the contract promises.
        Err(import::apply::ApplyError::Conflicts(c)) => return report_conflicts(cli, &c),
        Err(import::apply::ApplyError::WithOrphans { source, orphaned }) => {
            report_orphans(&orphaned);
            match *source {
                import::apply::ApplyError::Conflicts(c) => {
                    return report_conflicts(cli, &c);
                }
                other => return Err(anyhow::anyhow!("{other}")),
            }
        }
        // Typed non-conflict errors keep their own codes and exit
        // classification rather than collapsing to `usage`.
        Err(import::apply::ApplyError::Db(e)) => return Err(e.into()),
        Err(import::apply::ApplyError::Route(e)) => {
            return Err(pigeon_route::MutationError::Invalid(e).into());
        }
        Err(import::apply::ApplyError::Dkim(e)) => return Err(e.into()),
        Err(other) => return Err(anyhow::anyhow!("{other}")),
    };

    if cli.json {
        json::ok(serde_json::json!({
            "applied": true,
            "mode": mode_name(prepared.mode),
            "rows": prepared.plan.rows_read,
            "domains_created": applied.domains_created,
            "domains_matched": applied.domains_matched,
            "aliases_created": applied.aliases_created,
            "aliases_replaced": applied.aliases_replaced,
            "aliases_unchanged": applied.unchanged,
            "catchalls_set": applied.catchalls_set,
            "keys_generated": applied.keys_generated,
            "conflicts": [],
        }));
    } else {
        println!("Imported {} row(s).\n", prepared.plan.rows_read);
        println!("  {} domain(s) created", applied.domains_created);
        println!("  {} domain(s) already present", applied.domains_matched);
        println!("  {} alias(es) created", applied.aliases_created);
        if applied.aliases_replaced > 0 {
            println!("  {} alias(es) replaced", applied.aliases_replaced);
        }
        if applied.unchanged > 0 {
            println!("  {} alias(es) already correct", applied.unchanged);
        }
        if applied.catchalls_set > 0 {
            println!("  {} catch-all(s) set", applied.catchalls_set);
        }
        println!("  {} DKIM key(s) generated", applied.keys_generated);
    }

    note_reload(cli);
    Ok(exit::OK)
}

fn mode_name(mode: import::plan::Mode) -> &'static str {
    match mode {
        import::plan::Mode::Merge => "merge",
        import::plan::Mode::Replace => "replace",
    }
}

/// Steps 1, 2, 3 and 5, committing nothing.
///
/// Generates no keys, so it does not create `dkim_key` rows. That is sound —
/// the routing snapshot does not read them — and it is why a dry run proves the
/// *routing snapshot* builds rather than that the whole configuration is
/// serveable. The daemon refuses to start on a key it cannot verify, and a dry
/// run has no key to verify.
fn dry_run(
    cli: &Cli,
    conn: &mut rusqlite::Connection,
    prepared: &import::plan::Prepared,
) -> anyhow::Result<u8> {
    let outcome = pigeon_route::preview(conn, |tx| {
        let mut created = 0usize;
        for domain in &prepared.new_domains {
            pigeon_db::repo::add_domain(tx, domain, None)?;
            created += 1;
        }
        for (domain, rules) in &prepared.plan.domains {
            if prepared.mode == import::plan::Mode::Replace
                && prepared.existing_domains.contains(domain)
            {
                pigeon_db::repo::remove_all_aliases(tx, domain)?;
                pigeon_db::repo::clear_catchall(tx, domain)?;
            }
            for rule in rules.values() {
                if rule.is_catchall() {
                    pigeon_db::repo::set_catchall(tx, domain, rule.destinations.first())?;
                    continue;
                }
                let kind = if rule.reject {
                    pigeon_db::repo::AliasKind::Reject
                } else {
                    pigeon_db::repo::AliasKind::Forward
                };
                if pigeon_db::repo::list_aliases(tx, domain)?
                    .iter()
                    .any(|a| a.pattern == rule.pattern)
                {
                    continue;
                }
                pigeon_db::repo::add_alias(tx, domain, &rule.pattern, kind, &rule.destinations)?;
            }
        }
        Ok::<_, pigeon_db::DbError>(created)
    })?;

    if cli.json {
        json::ok(serde_json::json!({
            "applied": false,
            "mode": mode_name(prepared.mode),
            "rows": prepared.plan.rows_read,
            "domains_created": outcome.value,
            "domains_matched": prepared.existing_domains.len(),
            // Aliases only, and only the ones that would actually be created.
            // Reporting `rule_count` counted catch-alls as aliases and counted
            // rules already present and identical, so a dry run of a no-op
            // import claimed it would create everything in the file.
            "aliases_created": prepared.aliases_to_create(),
            "aliases_replaced": serde_json::Value::Null,
            "aliases_unchanged": prepared.unchanged,
            "catchalls_set": prepared.catchalls_to_set(),
            "keys_generated": 0,
            "conflicts": [],
        }));
    } else {
        println!("Would import {} row(s).\n", prepared.plan.rows_read);
        println!("  {} domain(s) created", outcome.value);
        println!(
            "  {} domain(s) already present",
            prepared.existing_domains.len()
        );
        println!("  {} alias(es) created", prepared.aliases_to_create());
        if prepared.catchalls_to_set() > 0 {
            println!("  {} catch-all(s) set", prepared.catchalls_to_set());
        }
        if prepared.unchanged > 0 {
            println!("  {} alias(es) already correct", prepared.unchanged);
        }
    }
    note(
        cli,
        "\nNothing was written, and no DKIM keys were generated. A dry run proves the file \
         parses and that the routing it produces is one Pigeon can serve — not that key \
         generation will succeed.",
    );
    Ok(exit::OK)
}

/// Name every key file a failed import could not remove.
///
/// stderr in both modes: it is a warning about the filesystem rather than part
/// of the command's result, and under `--json` the result is already the
/// conflict envelope, which must stay the only value on stdout.
fn report_orphans(orphaned: &[std::path::PathBuf]) {
    if orphaned.is_empty() {
        return;
    }
    eprintln!(
        "\nWarning: these key files were written by this import and could not be removed. \
         Nothing references them."
    );
    for p in orphaned {
        eprintln!("    {}", p.display());
    }
}

fn format_conflicts(conflicts: &[import::Conflict]) -> String {
    let mut out = format!("{} conflict(s); nothing was imported.\n", conflicts.len());
    for c in conflicts {
        out.push_str(&format!("\n  {c}"));
    }
    out
}

fn conflicts_json(conflicts: &[import::Conflict]) -> Vec<serde_json::Value> {
    conflicts
        .iter()
        .map(|c| {
            serde_json::json!({
                "row": if c.row == 0 { serde_json::Value::Null } else { serde_json::json!(c.row) },
                "address": c.address,
                "kind": c.kind.as_str(),
                "message": c.message,
            })
        })
        .collect()
}

fn report_conflicts(cli: &Cli, conflicts: &[import::Conflict]) -> anyhow::Result<u8> {
    if cli.json {
        // The failure envelope carries the list, so a consumer needs one shape
        // rather than two for the same command.
        println!(
            "{}",
            serde_json::json!({
                "format_version": 1,
                "error": {
                    "code": "import_conflicts",
                    "message": format!("{} conflict(s); nothing was imported", conflicts.len()),
                },
                "conflicts": conflicts_json(conflicts),
            })
        );
    } else {
        eprintln!("Error: {}", format_conflicts(conflicts));
    }
    Ok(exit::USAGE)
}

fn mode_required(cli: &Cli, scoped: &[import::plan::ExistingRouting]) -> anyhow::Result<u8> {
    let listed: Vec<String> = scoped.iter().map(|s| s.describe()).collect();
    let message = format!(
        "these domains already have routing this import could replace:\n\n  {}\n\n\
         An import file says what should exist, and nothing about what should stop \
         existing, so Pigeon will not guess:\n\n  \
         --merge    keep what is there; a differing alias is a conflict\n  \
         --replace  remove those aliases and catch-alls first (needs --yes)",
        listed.join("\n  ")
    );

    if cli.json {
        println!(
            "{}",
            serde_json::json!({
                "format_version": 1,
                "error": { "code": "mode_required", "message": message },
                "domains": scoped.iter().map(|s| serde_json::json!({
                    "domain": s.domain,
                    "aliases": s.aliases,
                    "catchall": s.catchall,
                })).collect::<Vec<_>>(),
            })
        );
    } else {
        eprintln!("Error: {message}");
    }
    Ok(exit::USAGE)
}

fn replace_needs_confirmation(cli: &Cli, prepared: &import::plan::Prepared) -> anyhow::Result<u8> {
    let aliases: usize = prepared.scoped.iter().map(|s| s.aliases).sum();
    let catchalls = prepared.scoped.iter().filter(|s| s.catchall).count();
    let message = format!(
        "--replace removes {aliases} alias(es) and {catchalls} catch-all(s) across \
         {} domain(s). Domain defaults are kept. Re-run with --yes.",
        prepared.scoped.len()
    );

    if cli.json {
        json::fail("confirmation_required", &message);
    } else {
        eprintln!("Error: {message}");
    }
    Ok(exit::USAGE)
}
