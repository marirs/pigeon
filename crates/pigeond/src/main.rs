//! The Pigeon daemon.
//!
//! # Startup gating
//!
//! Two classes of failure, deliberately treated differently:
//!
//! **Local and unambiguous — abort startup.** Unreadable database, failed
//! migration, unwritable spool, invalid TLS configuration, missing DKIM private
//! key for a signing domain, listener that will not bind. These are
//! misconfiguration, and running half-configured is worse than not running.
//!
//! **Remote DNS state — gate the individual domain, keep serving.** A domain
//! whose records regressed moves to `Error` and stops accepting its own mail.
//! The daemon still starts and other domains are unaffected.
//!
//! The distinction matters: a resolver outage must not turn into a total mail
//! outage across every domain on the host. Strictness belongs on the domain
//! lifecycle — nothing reaches `Active` without passing every check — not on
//! process startup.
//!
//! # Milestone 0
//!
//! This is the skeleton. Accepted mail is written to the spool directory and,
//! when `PIGEON_FORWARD_TO` is set, forwarded to a single hardcoded
//! destination resolved through its MX records. There is no routing table and
//! no queue: a forward that fails is logged and the spool copy is left where
//! it is, for an operator to find. Configuration comes from the environment
//! because the TOML loader and SQLite schema arrive in Milestone 1.

mod startup;

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pigeon_dns::{LookupError, MxError, MxLookup, SystemResolver, order_hosts};
use pigeon_smtp::{DataError, Envelope, Message, MessageSink, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Where a receiving MTA listens. Overridden only by tests.
const SUBMISSION_PORT: u16 = 25;

/// How long to wait for a receiving server to answer its door.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Deliveries attempted at once.
///
/// Inbound is capped too. Bounding one direction and not the other does not
/// make the process harder to exhaust — it only changes which resource runs
/// out first.
const MAX_CONCURRENT_DELIVERIES: usize = 32;

/// How long one message may spend being forwarded, across every host tried.
///
/// `pigeon_smtp::deliver` carries its own 30-minute budget, but that bounds a
/// single *connection*. The host loop below calls it once per MX record, so a
/// destination publishing ten exchanges that accept TCP and then go silent
/// held one of `MAX_CONCURRENT_DELIVERIES` permits for five hours. Bounding
/// the connection and not the delivery is the same mistake as bounding one
/// direction of concurrency and not the other: it changes which resource runs
/// out first, not whether one does.
const TOTAL_FORWARD_BUDGET: Duration = Duration::from_secs(1800);

/// Where forwarded mail is sent, and who we claim to be when sending it.
///
/// Generic over the resolver so delivery can be driven by `FakeResolver` in
/// tests. `MxLookup` returns `impl Future`, so it is not dyn-compatible and a
/// type parameter is the way to get the seam.
struct Forwarding<R: MxLookup> {
    resolver: Arc<R>,
    /// Name given in EHLO. Its forward and reverse DNS must agree with the
    /// sending address or receivers will treat everything as suspect.
    ehlo_name: String,
    destination: String,
    limit: Arc<Semaphore>,
    /// Always 25 in production. Injectable so a test can point the delivery
    /// path at a scripted peer on an ephemeral port instead of at the internet.
    port: u16,
    /// How long one message may spend being forwarded, across every host.
    ///
    /// A field rather than a constant for the same reason as `port`: a
    /// half-hour bound cannot be asserted against in a test suite, and a
    /// defence that is never exercised is one this project has repeatedly
    /// found to be broken.
    budget: Duration,
}

// Derived `Clone` would demand `R: Clone`, which the resolver need not be —
// every field is already shared behind an `Arc`.
impl<R: MxLookup> Clone for Forwarding<R> {
    fn clone(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            ehlo_name: self.ehlo_name.clone(),
            destination: self.destination.clone(),
            limit: Arc::clone(&self.limit),
            port: self.port,
            budget: self.budget,
        }
    }
}

/// Why a forward did not happen, keeping the distinction the delivery client
/// took the trouble to make.
///
/// `forward` used to return `Result<String, String>`. It consumed
/// `is_permanent()` internally to decide whether to try the next host and then
/// discarded it at the return, so the caller — and, from Milestone 3, the queue
/// deciding between retry and dead-letter — could not tell a refused recipient
/// from an unreachable network.
#[derive(Debug)]
enum ForwardError {
    /// Retrying will not help. Bounce rather than queue.
    Permanent(String),
    /// Worth trying again later.
    Transient(String),
}

impl ForwardError {
    fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permanent(m) => write!(f, "permanent: {m}"),
            Self::Transient(m) => write!(f, "transient: {m}"),
        }
    }
}

/// Where mail lands, and what is allowed to arrive.
struct SpoolSink<R: MxLookup> {
    dir: Arc<PathBuf>,
    /// Recipients to accept. Empty means accept anything, which is only
    /// reasonable while there is no real routing table.
    accept: Arc<HashSet<String>>,
    counter: Arc<AtomicU64>,
    /// Distinguishes identifiers from different runs of the process.
    boot: u32,
    /// Absent means spool and stop, which is useful for testing the receiver
    /// without sending anything onward.
    forwarding: Option<Forwarding<R>>,
}

// As with `Forwarding`: shared state behind `Arc`, so the resolver itself does
// not have to be `Clone` for the sink to be.
impl<R: MxLookup> Clone for SpoolSink<R> {
    fn clone(&self) -> Self {
        Self {
            dir: Arc::clone(&self.dir),
            accept: Arc::clone(&self.accept),
            counter: Arc::clone(&self.counter),
            boot: self.boot,
            forwarding: self.forwarding.clone(),
        }
    }
}

impl<R: MxLookup + 'static> MessageSink for SpoolSink<R> {
    fn accepts_recipient(&self, address: &str) -> bool {
        if self.accept.is_empty() {
            return true;
        }
        // Folds the domain only, matching `Address::same_mailbox` and RFC 5321
        // §2.4. Lowercasing the whole address made `Bob@example.com` in the
        // accept list authorise `bob@example.com` as well — a different
        // mailbox, and one the operator never listed. Over-accepting is not
        // mail loss, but it is the same folding mistake that was corrected in
        // the dedup path, and leaving one half of an invariant undone is how
        // it comes back.
        let Ok(parsed) = pigeon_types::Address::parse(address) else {
            return false;
        };
        self.accept
            .iter()
            .filter_map(|a| pigeon_types::Address::parse(a).ok())
            .any(|allowed| allowed.same_mailbox(&parsed))
    }

    async fn deliver(&self, message: Message) -> Result<String, DataError> {
        let id = self.next_id();
        let Message {
            envelope,
            received,
            body,
        } = message;

        match self.write_message(&id, &envelope, &received, &body).await {
            Ok(()) => {
                let from = display_sender(&envelope);
                tracing::info!(
                    %id,
                    %from,
                    to = ?envelope.recipients,
                    bytes = received.len() + body.len(),
                    "accepted"
                );

                // Acknowledge now that the message is durable, and forward
                // separately. Holding the SMTP session open for the length of
                // an onward delivery would make Pigeon's response time hostage
                // to the slowest receiving server in the world.
                //
                // Nothing retries yet: a failure here leaves the message in
                // the spool and says so. The queue arrives in Milestone 3.
                if let Some(f) = self.forwarding.clone() {
                    let rotation = self.counter.load(Ordering::Relaxed);
                    let id2 = id.clone();
                    let dir = Arc::clone(&self.dir);
                    let envelope = envelope.clone();

                    // The task carries an identifier, not a message. It re-reads
                    // the body from the spool file that was just fsynced, so a
                    // queue of pending deliveries costs a few hundred bytes each
                    // instead of pinning up to `max_message_size` apiece.
                    //
                    // This is why the permit is taken *inside* the task. An
                    // earlier attempt acquired it before spawning, to bound the
                    // number of pending tasks — but `deliver` is awaited by the
                    // SMTP session, so that parked the session on the outbound
                    // pool and made the 250 hostage to the slowest receiving
                    // server in the world, which is the exact thing the comment
                    // above says this design avoids. Worse: the sender times out
                    // inside its own DATA-ack window and retries, turning an
                    // unbounded-memory bug into a duplicate-delivery one.
                    tokio::spawn(async move {
                        let _permit = match f.limit.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::error!(id = %id2, "delivery limiter closed");
                                return;
                            }
                        };

                        let spooled = match tokio::fs::read(dir.join(format!("{id2}.eml"))).await {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::error!(id = %id2, error = %e, "cannot re-read spooled message");
                                return;
                            }
                        };

                        // The spooled file is already header-then-body, so it
                        // goes out as one part.
                        match forward(&f, rotation, &envelope, &spooled).await {
                            Ok(remote) => {
                                tracing::info!(id = %id2, %remote, "forwarded");
                                // Pigeon is a relay, not an archive. The spool
                                // copy exists to survive a crash between
                                // acceptance and delivery, and that window has
                                // now closed.
                                if let Err(e) = discard_spooled(&dir, &id2).await {
                                    tracing::warn!(id = %id2, error = %e, "could not clean spool");
                                }
                            }
                            // Kept on failure, deliberately: with no retry queue
                            // yet, this copy is the only thing between a
                            // transient failure and a lost message.
                            //
                            // The permanent/transient split is logged rather
                            // than acted on, because there is nothing yet to
                            // act with. Milestone 3's queue is what turns it
                            // into retry-or-dead-letter; until then it tells an
                            // operator reading the log whether the message is
                            // worth resending by hand.
                            Err(e) => tracing::error!(
                                id = %id2,
                                error = %e,
                                permanent = e.is_permanent(),
                                "forwarding failed; message left in spool"
                            ),
                        }
                    });
                }

                Ok(id)
            }
            Err(e) => {
                // A 451 tells the sender to try again later. Answering 250 for
                // a message that never reached disk would silently lose it,
                // since the sender then considers it delivered.
                tracing::error!(%id, error = %e, "could not spool message");
                Err(DataError::Temporary)
            }
        }
    }
}

impl<R: MxLookup> SpoolSink<R> {
    /// A spool identifier that will not collide with one from a previous run.
    ///
    /// The counter restarts at zero on every boot, so `secs-000000` is handed
    /// out again within any second the process starts in — and because failed
    /// messages are retained deliberately, a collision would overwrite mail
    /// that was already acknowledged. `boot` distinguishes runs; `create_new`
    /// in `write_durably` refuses to clobber if one slips through anyway.
    fn next_id(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{secs:010}-{boot:08x}-{n:06}", boot = self.boot)
    }

    /// Write the message so that it survives a crash.
    ///
    /// Temporary file, fsync, atomic rename, then fsync the directory. Only
    /// after all four is the caller entitled to answer 250 — a rename is not
    /// durable until the directory entry itself has been flushed.
    async fn write_message(
        &self,
        id: &str,
        envelope: &Envelope,
        received: &str,
        body: &[u8],
    ) -> io::Result<()> {
        // The envelope is kept beside the message rather than injected into it.
        // Adding headers would invalidate the sender's DKIM signature, which is
        // the one thing forwarding must not do.
        let meta = format!(
            "id: {id}\nfrom: {}\n{}",
            display_sender(envelope),
            envelope
                .recipients
                .iter()
                .map(|r| format!("to: {r}\n"))
                .collect::<String>()
        );

        write_durably(&self.dir, &format!("{id}.envelope"), &[meta.as_bytes()]).await?;
        // Header then body, written in sequence rather than concatenated, so
        // the message is not copied to prepend a few hundred bytes to it.
        write_durably(
            &self.dir,
            &format!("{id}.eml"),
            &[received.as_bytes(), body],
        )
        .await?;
        sync_dir(&self.dir).await
    }
}

/// What an earlier run left behind.
#[derive(Debug, Default, PartialEq, Eq)]
struct SpoolSurvey {
    /// Acknowledged messages that were never delivered.
    messages: usize,
    /// Temporary files from a write that never completed.
    partials: usize,
}

/// Look at what is in the spool, without changing any of it.
///
/// Partials are counted rather than removed. A sweep cannot tell an abandoned
/// temporary from one a concurrently running instance is writing this instant,
/// and deleting the second is destroying mail in flight to save a few bytes.
/// They are inert — `boot` differs per run, so no later identifier reuses the
/// name — but "harmless" and "invisible" are not the same thing, and an
/// operator whose disk is filling should be able to see why.
async fn survey_spool(dir: &Path) -> io::Result<SpoolSurvey> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut survey = SpoolSurvey::default();
    while let Some(e) = entries.next_entry().await? {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".eml") {
            survey.messages += 1;
        } else if name.starts_with('.') && name.ends_with(".partial") {
            survey.partials += 1;
        }
    }
    Ok(survey)
}

/// Remove a spooled message once it is safely somewhere else.
async fn discard_spooled(dir: &Path, id: &str) -> io::Result<()> {
    // Missing files are not an error: the operator may have cleaned up, and
    // failing here would only produce noise about work already done.
    for name in [format!("{id}.eml"), format!("{id}.envelope")] {
        match tokio::fs::remove_file(dir.join(&name)).await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    sync_dir(dir).await
}

/// Send one message onward.
///
/// Hosts are tried in preference order, but only for failures worth retrying.
/// A permanent rejection stops the attempt immediately: the backup MX for a
/// domain answers from the same mailbox database as the primary, so asking it
/// about a recipient the primary just refused only wastes time and makes the
/// sender look like it is probing.
async fn forward<R: MxLookup>(
    f: &Forwarding<R>,
    rotation: u64,
    envelope: &Envelope,
    message: &[u8],
) -> Result<String, ForwardError> {
    // The whole forward, not one connection. Every wait below is measured
    // against this, so the total cost of a message is bounded however many
    // hosts the destination publishes.
    let deadline = Instant::now() + f.budget;

    let domain = f
        .destination
        .rsplit_once('@')
        .map(|(_, d)| d)
        .ok_or_else(|| {
            // Startup validates the destination, so reaching this means the
            // guard was bypassed. Permanent either way: retrying will not add
            // an '@'.
            ForwardError::Permanent(format!("destination {} has no domain", f.destination))
        })?;

    let hosts = match f.resolver.lookup_mx(domain).await {
        Ok(records) => order_hosts(&records, rotation).map_err(|e| match e {
            // The domain has said in DNS that it accepts no mail. Retrying is
            // not politeness, it is ignoring the answer.
            MxError::NullMx => ForwardError::Permanent(e.to_string()),
            // Records exist but none is usable — malformed exchanges, say.
            // Transient: the zone may be mid-edit, and this is the direction
            // that does not bounce mail which would have delivered.
            MxError::NoUsableHost => ForwardError::Transient(e.to_string()),
        })?,
        // A domain with no MX still accepts mail at its own address record.
        // This is the implicit MX rule, and skipping it loses mail to small
        // domains that never published one.
        Err(LookupError::NoRecords(_)) => vec![domain.to_string()],
        Err(e) if e.is_permanent() => return Err(ForwardError::Permanent(e.to_string())),
        Err(e) => return Err(ForwardError::Transient(e.to_string())),
    };

    // The envelope Pigeon sends is its own: one recipient, the configured
    // destination. Rewriting the sender for SPF comes with SRS in Milestone 2.
    let outgoing = Envelope {
        sender: envelope.sender.clone(),
        recipients: vec![f.destination.clone()],
    };

    // Transient by default: having tried nothing is not evidence that the
    // destination is refusing.
    let mut last = ForwardError::Transient("no hosts tried".into());

    for host in &hosts {
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            tracing::warn!(%host, "forward budget exhausted; remaining hosts not tried");
            return Err(ForwardError::Transient(
                "overall forward budget exhausted".into(),
            ));
        };

        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT.min(remaining),
            TcpStream::connect((host.as_str(), f.port)),
        );

        let stream = match connect.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                last = ForwardError::Transient(format!("{host}: {e}"));
                tracing::warn!(%host, error = %e, "connect failed, trying next host");
                continue;
            }
            Err(_) => {
                last = ForwardError::Transient(format!("{host}: connect timed out"));
                tracing::warn!(%host, "connect timed out, trying next host");
                continue;
            }
        };

        // Recomputed: the connect above consumed part of the budget.
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Err(ForwardError::Transient(
                "overall forward budget exhausted".into(),
            ));
        };

        // Bound to outlive the future that borrows it.
        let parts: [&[u8]; 1] = [message];
        let attempt = tokio::time::timeout(
            remaining,
            pigeon_smtp::deliver(stream, &f.ehlo_name, &outgoing, &parts),
        );

        match attempt.await {
            Ok(Ok(accepted)) => return Ok(accepted.message),
            // A permanent rejection stops the attempt immediately: the backup
            // MX for a domain answers from the same mailbox database as the
            // primary, so asking it about a recipient the primary just refused
            // only wastes time and makes the sender look like it is probing.
            Ok(Err(e)) if e.is_permanent() => {
                return Err(ForwardError::Permanent(format!("{host}: {e}")));
            }
            Ok(Err(e)) => {
                last = ForwardError::Transient(format!("{host}: {e}"));
                tracing::warn!(%host, error = %e, "temporary failure, trying next host");
            }
            Err(_) => {
                last = ForwardError::Transient(format!("{host}: forward budget exhausted"));
                tracing::warn!(%host, "forward budget exhausted mid-delivery");
            }
        }
    }

    Err(last)
}

/// The null sender prints as `<>` rather than as nothing, so a bounce is
/// distinguishable from a truncated log line.
fn display_sender(envelope: &Envelope) -> &str {
    if envelope.sender.is_empty() {
        "<>"
    } else {
        envelope.sender.as_str()
    }
}

async fn write_durably(dir: &Path, name: &str, parts: &[&[u8]]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.partial"));
    let final_path = dir.join(name);

    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    // 0600, not whatever the umask happens to be. A spooled file is the
    // plaintext body of somebody's mail; the default 0666 & ~umask is
    // typically 0644, which makes every message on the host world-readable to
    // any local account. `SECURITY.md` states this requirement and the code
    // did not implement it.
    #[cfg(unix)]
    options.mode(0o600);

    let mut f = options.open(&tmp).await?;
    for part in parts {
        f.write_all(part).await?;
    }
    f.sync_all().await?;
    drop(f);

    // Refuse to overwrite an existing message. A spooled file belongs to a
    // message that was already acknowledged and may still be awaiting a
    // delivery that failed; replacing it destroys mail the sender believes was
    // accepted.
    //
    // `hard_link` rather than `rename`, because `rename` replaces its
    // destination unconditionally — so `create_new` on the temporary file
    // alone prevents nothing, and a prior `try_exists` check is a race with a
    // window between the two calls. Linking fails with `AlreadyExists` if the
    // destination is taken, atomically, which is the property actually wanted.
    let link = tokio::fs::hard_link(&tmp, &final_path).await;

    // The temporary file goes either way: on success it is a second name for
    // content now reachable under the final one, and on failure it is a
    // partial message nothing will ever read.
    let removed = tokio::fs::remove_file(&tmp).await;

    match link {
        Ok(()) => {
            if let Err(e) = removed {
                tracing::warn!(path = %tmp.display(), error = %e, "could not remove spool temporary");
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "spool identifier collision: {} already exists",
                final_path.display()
            ),
        )),
        Err(e) => Err(e),
    }
}

/// Create the spool directory and prove it is actually usable.
///
/// `create_dir_all` succeeds on a directory that already exists and is
/// read-only, so on its own it does not support the startup-gating promise
/// this module opens by making. The probe writes, fsyncs and removes a file by
/// the same route a message takes, which is the only way to learn that the
/// path is writable, that fsync works on it, and that the process is not out
/// of space or inodes — before the listener binds and a sender is told 250.
async fn prepare_spool(dir: &Path) -> io::Result<()> {
    tokio::fs::create_dir_all(dir).await?;

    // 0700 on a directory we created. Restricting an existing one is not our
    // decision to make — the operator may have set a group deliberately — but
    // the permissions are logged below so a permissive spool is visible rather
    // than assumed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = tokio::fs::metadata(dir).await?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %dir.display(),
                mode = format!("{mode:04o}"),
                "spool directory is accessible to other local users; 0700 is expected"
            );
        }
    }

    let probe = dir.join(".pigeon-writable-probe");
    // Best effort: a probe stranded by an earlier crash must not make startup
    // fail for a spool that is otherwise fine.
    let _ = tokio::fs::remove_file(&probe).await;

    write_durably(dir, ".pigeon-writable-probe", &[b"probe"]).await?;
    sync_dir(dir).await?;
    tokio::fs::remove_file(&probe).await?;
    sync_dir(dir).await
}

/// Flush the directory entry, so the rename itself is durable.
async fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::File::open(&dir)?.sync_all())
        .await
        .map_err(io::Error::other)?
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // `Display`, not `Debug`. Returning `Result` from `main` prints the
            // debug form, which renders a multi-line explanation as one line of
            // escaped `\n` — and every startup error here is a paragraph
            // telling an operator what to do about it.
            eprintln!("pigeond: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Milestone 1 configuration when a file is named, Milestone 0 environment
    // variables otherwise.
    //
    // Both paths exist on purpose and only for now. `startup::start` runs the
    // whole ordered sequence — validate, migrate, cross-check, probe the spool —
    // but routing still comes from `PIGEON_ACCEPT`, because the routing snapshot
    // is what replaces it and the snapshot builder is not written. Wiring the
    // config file to a routing table that does not exist would be pretending.
    //
    // The environment path goes away when the snapshot builder lands, and with
    // it `PIGEON_ACCEPT` and `PIGEON_FORWARD_TO`.
    let booted = match std::env::var("PIGEON_CONFIG") {
        Ok(path) if !path.trim().is_empty() => {
            let started = startup::start(Path::new(path.trim()), |dir| async move {
                prepare_spool(&dir).await
            })
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e}")))?;

            if started.migration.is_empty() {
                tracing::info!(version = started.migration.to, "database schema up to date");
            } else {
                tracing::info!(
                    from = started.migration.from,
                    to = started.migration.to,
                    applied = ?started.migration.versions,
                    backup = ?started.migration.backup,
                    "database migrated"
                );
            }
            for w in &started.warnings {
                tracing::warn!("{w}");
            }

            // The routing table is built and validated — every rule in it has
            // passed the checks SQLite cannot make — but it is not yet what
            // decides where mail goes. Acceptance still comes from
            // `PIGEON_ACCEPT` and delivery from `PIGEON_FORWARD_TO`.
            //
            // Wiring acceptance to the snapshot while delivery still goes to
            // one hardcoded address would accept mail for `hello@example.com`
            // on the strength of a rule and then ignore where that rule points.
            // Connecting both means fanning one message out to several
            // destinations with per-recipient outcomes, which needs the
            // Milestone 3 queue — finding 19 is the same gap seen from the
            // delivery side.
            //
            // So it is reported rather than half-used, and the log says which.
            let domains = started.snapshot.domain_names().count();
            let schema = pigeon_db::schema_version(&started.db).unwrap_or(0);
            tracing::info!(schema, "control plane open");
            tracing::info!(
                domains,
                "routing table built and validated. It is not serving yet: acceptance \
                 still comes from PIGEON_ACCEPT and delivery from PIGEON_FORWARD_TO."
            );

            Some(started)
        }
        _ => {
            tracing::warn!(
                "PIGEON_CONFIG is unset: running on Milestone 0 environment configuration.                  No database, no routing table, no DNS validation."
            );
            None
        }
    };

    let listen = match &booted {
        Some(b) => b.config.config().smtp.inbound.listen.to_string(),
        None => env_or("PIGEON_LISTEN", "127.0.0.1:2525"),
    };
    let hostname = match &booted {
        Some(b) => b.config.config().hostname.clone(),
        None => env_or("PIGEON_HOSTNAME", "localhost"),
    };
    let spool = match &booted {
        Some(b) => b.config.config().spool.clone(),
        None => PathBuf::from(env_or("PIGEON_SPOOL", "./spool")),
    };

    // Case preserved. The local part belongs to the destination host and only
    // the domain may be folded, which `accepts_recipient` does at comparison
    // time — see `Address::same_mailbox`.
    let accept: HashSet<String> = env_or("PIGEON_ACCEPT", "")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Entries that cannot be parsed would silently never match, so a typo in
    // the accept list would present as mail being refused for no stated
    // reason. Local, unambiguous misconfiguration: stop startup.
    for entry in &accept {
        if pigeon_types::Address::parse(entry).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("PIGEON_ACCEPT contains an invalid address: {entry:?}"),
            ));
        }
    }

    // Already done inside `startup::start` on the config path, in the ordered
    // position. Repeating it here would probe twice and, worse, would put step 6
    // after step 8 for one of the two paths.
    if booted.is_none() {
        // An unusable spool is local, unambiguous misconfiguration, so it stops
        // startup rather than being discovered on the first message.
        prepare_spool(&spool).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("spool directory {} is unusable: {e}", spool.display()),
            )
        })?;
    }
    let sink_dir = spool.clone();

    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {listen}: {e}")))?;

    if accept.is_empty() {
        tracing::warn!(
            "PIGEON_ACCEPT is unset: accepting every recipient. \
             Set it to a comma-separated list once you have real addresses."
        );
    }

    tracing::info!(
        %listen,
        %hostname,
        spool = %spool.display(),
        recipients = accept.len(),
        "pigeond listening"
    );

    // A resolver that cannot be built is local misconfiguration and stops
    // startup. A resolver that later fails to answer is not, and must not.
    let forwarding = match std::env::var("PIGEON_FORWARD_TO") {
        Ok(destination) if !destination.trim().is_empty() => {
            let destination = destination.trim().to_string();

            // Local, unambiguous misconfiguration, so it stops startup — the
            // policy this module opens by stating. Checked here rather than
            // per-message because the alternative is a daemon that starts
            // cleanly, answers 250 to everything, and fails every delivery.
            if pigeon_types::Address::parse(&destination).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("PIGEON_FORWARD_TO is not a valid address: {destination:?}"),
                ));
            }

            let resolver = SystemResolver::from_system()
                .map_err(|e| io::Error::other(format!("cannot build resolver: {e}")))?;
            tracing::info!(%destination, "forwarding enabled");
            Some(Forwarding {
                resolver: Arc::new(resolver),
                ehlo_name: hostname.clone(),
                destination,
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: SUBMISSION_PORT,
                budget: TOTAL_FORWARD_BUDGET,
            })
        }
        _ => {
            tracing::info!("PIGEON_FORWARD_TO is unset: messages will be spooled only");
            None
        }
    };

    // Anything already in the spool was accepted by a previous run and never
    // delivered. Nothing rescans it yet, so the least Pigeon can do is refuse
    // to let it pass unnoticed — an operator who is never told has no way to
    // discover it except by looking.
    match survey_spool(&sink_dir).await {
        Ok(s) => {
            if s.messages > 0 {
                tracing::warn!(
                    stranded = s.messages,
                    path = %sink_dir.display(),
                    "spool is not empty: these messages were acknowledged but never delivered, \
                     and nothing will retry them. Inspect and resend or remove them."
                );
            }
            if s.partials > 0 {
                // Not removed here: see `survey_spool`. Named so that disk
                // consumed by a crash loop is attributable rather than
                // mysterious.
                tracing::warn!(
                    partials = s.partials,
                    path = %sink_dir.display(),
                    "spool holds incomplete temporary files from writes that never finished. \
                     They are never read and never retried; remove them once no other \
                     pigeond is running against this spool."
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not read the spool directory"),
    }

    let sink = SpoolSink {
        dir: Arc::new(sink_dir),
        accept: Arc::new(accept),
        counter: Arc::new(AtomicU64::new(0)),
        boot: std::process::id(),
        forwarding,
    };

    let config = ServerConfig {
        hostname,
        // TLS arrives with the rest of Milestone 5; advertising it now would
        // invite clients to negotiate something that does not exist.
        tls_available: false,
        ..Default::default()
    };

    tokio::select! {
        r = pigeon_smtp::serve(listener, config, sink) => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    /// A private directory that removes itself.
    ///
    /// A dependency for this would be three lines of `Cargo.toml` and a new
    /// entry in the reviewed dependency set, for something the standard
    /// library already does.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let unique = format!(
                "pigeond-test-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            // Best effort: a failure here must not mask the test's own result.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A sink that spools and stops. `FakeResolver` names the type parameter
    /// without ever being asked anything.
    fn sink(dir: &Path, accept: &[&str]) -> SpoolSink<pigeon_dns::FakeResolver> {
        SpoolSink {
            dir: Arc::new(dir.to_path_buf()),
            accept: Arc::new(accept.iter().map(|s| s.to_string()).collect()),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x1234_5678,
            forwarding: None,
        }
    }

    #[tokio::test]
    async fn spooled_messages_are_written_durably_and_read_back_intact() {
        let tmp = TempDir::new("write");
        write_durably(tmp.path(), "m.eml", &[b"Received: x\r\n", b"body\r\n"])
            .await
            .expect("write");

        assert_eq!(
            tokio::fs::read(tmp.path().join("m.eml")).await.unwrap(),
            b"Received: x\r\nbody\r\n",
            "parts must land in order, with nothing between them"
        );

        // The temporary is a partial message under a name nothing reads. It
        // must not survive to be counted as stranded mail at the next startup.
        assert!(
            !tmp.path().join(".m.eml.partial").exists(),
            "temporary file left behind"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn spooled_messages_are_not_readable_by_other_local_users() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new("perms");
        write_durably(tmp.path(), "m.eml", &[b"secret"])
            .await
            .expect("write");

        // The default is 0666 & ~umask, typically 0644 — every message on the
        // host readable by any local account. `SECURITY.md` requires otherwise.
        let mode = tokio::fs::metadata(tmp.path().join("m.eml"))
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "spool file mode is {mode:04o}, want 0600");
    }

    #[tokio::test]
    async fn a_spool_collision_is_refused_without_destroying_the_original() {
        let tmp = TempDir::new("collide");
        write_durably(tmp.path(), "m.eml", &[b"first"])
            .await
            .expect("first write");

        let err = write_durably(tmp.path(), "m.eml", &[b"second"])
            .await
            .expect_err("collision was not refused");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);

        // The point of refusing: the existing file is mail that was already
        // acknowledged and may still be awaiting a delivery that failed.
        assert_eq!(
            tokio::fs::read(tmp.path().join("m.eml")).await.unwrap(),
            b"first",
            "an acknowledged message was overwritten"
        );
        assert!(
            !tmp.path().join(".m.eml.partial").exists(),
            "failed write left its temporary behind"
        );
    }

    #[tokio::test]
    async fn a_stranded_temporary_is_refused_rather_than_truncated() {
        let tmp = TempDir::new("stranded");
        // What a crash between create and link leaves behind.
        tokio::fs::write(tmp.path().join(".m.eml.partial"), b"partial")
            .await
            .unwrap();

        let err = write_durably(tmp.path(), "m.eml", &[b"body"])
            .await
            .expect_err("expected the temporary name to be taken");
        assert_eq!(
            err.kind(),
            io::ErrorKind::AlreadyExists,
            "must fail loudly rather than truncate a partial message"
        );
        // Answered 451, so the sender retries under a new identifier. The
        // alternative — truncating — is silent.
        //
        // Stranded temporaries are not swept at startup, deliberately: nothing
        // proves another instance is not writing one, and a sweep that races a
        // live daemon destroys mail in flight. They are inert — no identifier
        // from a later run reuses the name, because `boot` differs.
    }

    #[tokio::test]
    async fn a_message_writes_both_files_and_discard_removes_both() {
        let tmp = TempDir::new("message");
        let s = sink(tmp.path(), &[]);
        let envelope = Envelope {
            sender: "sender@example.com".into(),
            recipients: vec!["a@example.net".into(), "b@example.net".into()],
        };

        let id = s.next_id();
        s.write_message(&id, &envelope, "Received: here\r\n", b"body\r\n")
            .await
            .expect("write_message");

        let eml = tokio::fs::read(tmp.path().join(format!("{id}.eml")))
            .await
            .unwrap();
        assert_eq!(eml, b"Received: here\r\nbody\r\n");

        let meta = tokio::fs::read_to_string(tmp.path().join(format!("{id}.envelope")))
            .await
            .unwrap();
        assert!(meta.contains("from: sender@example.com"), "{meta}");
        assert!(meta.contains("to: a@example.net"), "{meta}");
        assert!(meta.contains("to: b@example.net"), "{meta}");

        assert_eq!(survey_spool(tmp.path()).await.unwrap().messages, 1);
        discard_spooled(tmp.path(), &id).await.expect("discard");
        assert_eq!(
            survey_spool(tmp.path()).await.unwrap().messages,
            0,
            "a forwarded message was left in the spool"
        );
        assert!(!tmp.path().join(format!("{id}.envelope")).exists());
    }

    #[tokio::test]
    async fn discarding_a_message_twice_is_not_an_error() {
        // The operator may have cleaned up by hand, and a second failure here
        // would only produce noise about work already done.
        let tmp = TempDir::new("discard");
        discard_spooled(tmp.path(), "absent")
            .await
            .expect("discard");
    }

    #[tokio::test]
    async fn the_null_sender_is_recorded_as_a_bounce_not_as_nothing() {
        let tmp = TempDir::new("bounce");
        let s = sink(tmp.path(), &[]);
        let envelope = Envelope {
            sender: String::new(),
            recipients: vec!["a@example.net".into()],
        };

        let id = s.next_id();
        s.write_message(&id, &envelope, "", b"body\r\n")
            .await
            .unwrap();

        let meta = tokio::fs::read_to_string(tmp.path().join(format!("{id}.envelope")))
            .await
            .unwrap();
        assert!(meta.contains("from: <>"), "truncated log line: {meta}");
    }

    #[test]
    fn identifiers_do_not_repeat_within_a_run() {
        let tmp = TempDir::new("ids");
        let s = sink(tmp.path(), &[]);
        let ids: HashSet<String> = (0..1000).map(|_| s.next_id()).collect();
        assert_eq!(ids.len(), 1000, "identifier collision within one run");
    }

    #[test]
    fn the_accept_list_folds_the_domain_and_not_the_local_part() {
        let tmp = TempDir::new("accept");
        let s = sink(tmp.path(), &["Bob@Example.com"]);

        assert!(s.accepts_recipient("Bob@example.com"), "domain not folded");
        assert!(s.accepts_recipient("Bob@EXAMPLE.COM"), "domain not folded");
        // A different mailbox, and one the operator never listed. RFC 5321
        // §2.4 reserves the local part to the destination host.
        assert!(
            !s.accepts_recipient("bob@example.com"),
            "folded the local part"
        );
    }

    #[test]
    fn an_empty_accept_list_accepts_anything() {
        let tmp = TempDir::new("accept-any");
        let s = sink(tmp.path(), &[]);
        assert!(s.accepts_recipient("whoever@example.com"));
    }

    #[test]
    fn malformed_recipients_are_not_accepted_by_a_configured_list() {
        let tmp = TempDir::new("accept-bad");
        let s = sink(tmp.path(), &["a@example.com"]);
        assert!(!s.accepts_recipient("not-an-address"));
        assert!(!s.accepts_recipient("x@."));
    }

    #[tokio::test]
    async fn preparing_the_spool_creates_it_and_leaves_no_probe_behind() {
        let tmp = TempDir::new("prepare");
        let spool = tmp.path().join("nested").join("spool");

        prepare_spool(&spool).await.expect("prepare");
        assert!(spool.is_dir());
        assert_eq!(
            survey_spool(&spool).await.unwrap().messages,
            0,
            "the probe was counted as stranded mail"
        );
        assert!(
            !spool.join(".pigeon-writable-probe").exists(),
            "probe left behind"
        );

        // Running twice must be fine: the daemon restarts.
        prepare_spool(&spool).await.expect("prepare again");
    }

    // ------------------------------------------------- the whole path, once
    //
    // Every other test here stops at a function boundary, and the integration
    // tests in `pigeon-smtp` stop at a synthetic sink. Nothing walked
    // listener → session → spool → resolver → delivery client → receiving
    // server in one run, which is the path a real message actually takes.

    /// Drive the real server with the real sink against a scripted peer.
    ///
    /// The resolver is fake and the port is injected, so no DNS is consulted
    /// and nothing leaves the loopback interface — but every other component
    /// is the production one.
    async fn spawn_daemon(
        dir: &Path,
        accept: &[&str],
        peer_addr: SocketAddr,
    ) -> (SocketAddr, Arc<PathBuf>) {
        spawn_daemon_with_budget(dir, accept, peer_addr, TOTAL_FORWARD_BUDGET).await
    }

    async fn spawn_daemon_with_budget(
        dir: &Path,
        accept: &[&str],
        peer_addr: SocketAddr,
        budget: Duration,
    ) -> (SocketAddr, Arc<PathBuf>) {
        use pigeon_dns::{FakeResolver, MxRecord};

        let spool = Arc::new(dir.to_path_buf());
        let resolver = FakeResolver::new().with(
            "example.net",
            vec![MxRecord::new(10, peer_addr.ip().to_string())],
        );

        let sink = SpoolSink {
            dir: Arc::clone(&spool),
            accept: Arc::new(accept.iter().map(|s| s.to_string()).collect()),
            counter: Arc::new(AtomicU64::new(0)),
            boot: 0x0bad_cafe,
            forwarding: Some(Forwarding {
                resolver: Arc::new(resolver),
                ehlo_name: "pigeon.test".into(),
                destination: "dest@example.net".into(),
                limit: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
                port: peer_addr.port(),
                budget,
            }),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let config = ServerConfig {
            hostname: "pigeon.test".into(),
            ..ServerConfig::default()
        };
        tokio::spawn(async move {
            let _ = pigeon_smtp::serve(listener, config, sink).await;
        });
        (addr, spool)
    }

    /// Send one message through a real SMTP conversation.
    async fn submit(addr: SocketAddr, from: &str, to: &str, body: &str) -> Vec<(u16, String)> {
        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        let mut replies = Vec::new();
        replies.push(c.read_reply().await.expect("banner"));

        for line in [
            "EHLO sender.test\r\n".to_string(),
            format!("MAIL FROM:<{from}>\r\n"),
            format!("RCPT TO:<{to}>\r\n"),
            "DATA\r\n".to_string(),
        ] {
            c.send(line.as_bytes()).await.expect("send");
            replies.push(c.read_reply().await.expect("reply"));
        }

        c.send(body.as_bytes()).await.expect("body");
        c.send(b".\r\n").await.expect("terminator");
        replies.push(c.read_reply().await.expect("data ack"));

        c.send(b"QUIT\r\n").await.expect("quit");
        replies.push(c.read_reply().await.expect("bye"));
        replies
    }

    /// Poll until the spool is empty or the wait is unreasonable.
    ///
    /// Forwarding happens on a detached task after the `250`, so there is no
    /// handle to await. Polling a real condition beats sleeping a fixed time,
    /// which is either flaky or slow and usually both.
    async fn wait_until_spool_is_empty(dir: &Path) -> bool {
        for _ in 0..200 {
            if survey_spool(dir).await.map(|s| s.messages).unwrap_or(1) == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        false
    }

    #[tokio::test]
    async fn a_message_travels_from_the_listener_to_a_receiving_server() {
        let tmp = TempDir::new("e2e");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;

        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "Subject: hi\r\n\r\nbody line\r\n",
        )
        .await;

        // Banner, EHLO, MAIL, RCPT, DATA, end-of-data, QUIT.
        assert_eq!(replies[0].0, 220, "banner: {:?}", replies[0]);
        assert_eq!(replies[5].0, 250, "message not accepted: {:?}", replies[5]);

        assert!(
            wait_until_spool_is_empty(&spool).await,
            "the message was never forwarded, or the spool was not cleaned"
        );

        // The receiving end saw a real SMTP transaction, not just a connection.
        assert!(transcript.saw("EHLO"), "{:?}", transcript.lines());
        assert!(
            transcript.saw("MAIL FROM:<sender@remote.test>"),
            "envelope sender not passed through: {:?}",
            transcript.lines()
        );
        assert!(
            transcript.saw("RCPT TO:<dest@example.net>"),
            "not readdressed to the configured destination: {:?}",
            transcript.lines()
        );

        // The body that arrived, with the trace header Pigeon prepended.
        let body = transcript
            .lines()
            .into_iter()
            .find(|l| l.contains("body line"))
            .expect("body never reached the peer");
        assert!(
            body.starts_with("Received: from sender.test"),
            "no trace header, or not first: {body:?}"
        );
        assert!(body.contains("Subject: hi"));
    }

    #[tokio::test]
    async fn a_refused_recipient_never_reaches_the_spool() {
        let tmp = TempDir::new("e2e-refused");
        let (peer_addr, transcript) = pigeon_testkit::Peer::accepting().spawn().await;
        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;

        let mut c = pigeon_testkit::RawClient::connect(addr)
            .await
            .expect("connect");
        c.read_reply().await.expect("banner");
        c.send(b"EHLO sender.test\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"MAIL FROM:<sender@remote.test>\r\n").await.unwrap();
        c.read_reply().await.unwrap();
        c.send(b"RCPT TO:<nobody@example.com>\r\n").await.unwrap();
        let (code, text) = c.read_reply().await.expect("rcpt reply");

        // Refused during the conversation, so the sender keeps responsibility.
        // Accepting and then discarding is never acceptable.
        assert_eq!(code, 550, "{text}");
        assert_eq!(survey_spool(&spool).await.unwrap().messages, 0);
        assert!(
            !transcript.saw("MAIL FROM"),
            "a refused recipient still triggered an outbound delivery"
        );
    }

    #[tokio::test]
    async fn a_message_the_receiver_rejects_stays_in_the_spool() {
        let tmp = TempDir::new("e2e-rejected");

        // A receiving server that refuses the recipient outright.
        let (peer_addr, _transcript) = pigeon_testkit::Peer::new()
            .send("220 strict.test ESMTP")
            .read_line() // EHLO
            .send("250 strict.test")
            .read_line() // MAIL FROM
            .send("250 Ok")
            .read_line() // RCPT TO
            .send("550 No such user")
            .close()
            .spawn()
            .await;

        let (addr, spool) = spawn_daemon(tmp.path(), &["hello@example.com"], peer_addr).await;
        let replies = submit(
            addr,
            "sender@remote.test",
            "hello@example.com",
            "Subject: hi\r\n\r\nbody\r\n",
        )
        .await;
        assert_eq!(replies[5].0, 250, "acceptance is independent of forwarding");

        // With no retry queue, the spool copy is the only thing between a
        // failed forward and a lost message. It must survive.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            survey_spool(&spool).await.unwrap().messages,
            1,
            "a message that could not be delivered was deleted anyway"
        );
    }

    #[tokio::test]
    async fn the_forward_budget_bounds_the_whole_delivery_not_one_connection() {
        // A peer that answers its door and then says nothing. `deliver` has
        // its own 30-minute budget, so without an outer deadline this task
        // would hold one of 32 delivery permits for 30 minutes per MX host.
        let (peer_addr, _t) = pigeon_testkit::Peer::new()
            .send("220 slow.test ESMTP")
            .stall(Duration::from_secs(60))
            .close()
            .spawn()
            .await;

        let f = Forwarding {
            resolver: Arc::new(pigeon_dns::FakeResolver::new().with(
                "example.net",
                vec![
                    // Three hosts. The bound is on the sum, so a per-connection
                    // budget would take three times as long to give up.
                    pigeon_dns::MxRecord::new(10, peer_addr.ip().to_string()),
                    pigeon_dns::MxRecord::new(20, peer_addr.ip().to_string()),
                    pigeon_dns::MxRecord::new(30, peer_addr.ip().to_string()),
                ],
            )),
            ehlo_name: "pigeon.test".into(),
            destination: "dest@example.net".into(),
            limit: Arc::new(Semaphore::new(1)),
            port: peer_addr.port(),
            budget: Duration::from_millis(400),
        };

        let envelope = Envelope {
            sender: "s@remote.test".into(),
            recipients: vec!["hello@example.com".into()],
        };

        let started = Instant::now();
        let err = forward(&f, 0, &envelope, b"body\r\n")
            .await
            .expect_err("a stalled peer somehow delivered");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the budget did not bound the delivery: took {:?}",
            started.elapsed()
        );
        // Transient: a peer that stopped talking says nothing about whether
        // the recipient exists, and bouncing on it would lose deliverable mail.
        assert!(
            !err.is_permanent(),
            "a stall was reported as permanent: {err}"
        );
    }

    #[tokio::test]
    async fn a_null_mx_is_permanent_and_a_resolver_fault_is_not() {
        // The distinction `forward` used to flatten into a String. Milestone
        // 3's queue chooses between retry and dead-letter on exactly this.
        let envelope = Envelope {
            sender: "s@remote.test".into(),
            recipients: vec!["hello@example.com".into()],
        };

        let f = |resolver| Forwarding {
            resolver: Arc::new(resolver),
            ehlo_name: "pigeon.test".into(),
            destination: "dest@example.net".into(),
            limit: Arc::new(Semaphore::new(1)),
            port: 1,
            budget: Duration::from_millis(400),
        };

        // RFC 7505: the domain has published that it accepts no mail.
        let null_mx = f(pigeon_dns::FakeResolver::new()
            .with("example.net", vec![pigeon_dns::MxRecord::new(0, ".")]));
        let err = forward(&null_mx, 0, &envelope, b"body\r\n")
            .await
            .expect_err("null MX delivered");
        assert!(err.is_permanent(), "null MX treated as retryable: {err}");

        // A resolver that is merely failing says nothing about the domain.
        let broken = f(pigeon_dns::FakeResolver::new().failing(
            "example.net",
            pigeon_dns::LookupError::Resolver("SERVFAIL".into()),
        ));
        let err = forward(&broken, 0, &envelope, b"body\r\n")
            .await
            .expect_err("a broken resolver delivered");
        assert!(
            !err.is_permanent(),
            "a resolver fault would have bounced deliverable mail: {err}"
        );

        // A name that genuinely does not exist is permanent.
        let gone = f(pigeon_dns::FakeResolver::new().failing(
            "example.net",
            pigeon_dns::LookupError::NoSuchDomain("example.net".into()),
        ));
        let err = forward(&gone, 0, &envelope, b"body\r\n")
            .await
            .expect_err("NXDOMAIN delivered");
        assert!(err.is_permanent(), "NXDOMAIN treated as retryable: {err}");
    }

    #[tokio::test]
    async fn the_spool_survey_separates_messages_from_abandoned_temporaries() {
        let tmp = TempDir::new("survey");
        write_durably(tmp.path(), "a.eml", &[b"one"]).await.unwrap();
        write_durably(tmp.path(), "a.envelope", &[b"meta"])
            .await
            .unwrap();
        // What a crash between create and link leaves.
        tokio::fs::write(tmp.path().join(".b.eml.partial"), b"half")
            .await
            .unwrap();

        let survey = survey_spool(tmp.path()).await.unwrap();
        assert_eq!(
            survey,
            SpoolSurvey {
                messages: 1,
                partials: 1
            },
            "an envelope was counted as a message, or a partial was invisible"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn preparing_an_unwritable_spool_fails_before_the_listener_binds() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new("readonly");
        let spool = tmp.path().join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o500)).unwrap();

        // `create_dir_all` succeeds on a directory that already exists, so
        // without the probe this is the case that starts cleanly, binds, and
        // answers 451 to every message instead of refusing to run.
        let result = prepare_spool(&spool).await;
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            // Root ignores the mode bits, so the probe legitimately succeeds
            // and there is nothing here to assert. Skipping is honest; a
            // `geteuid` binding to detect it is more machinery than the check
            // is worth.
            Ok(()) => eprintln!("skipped: the permission bits did not apply (running as root?)"),
        }
    }
}
