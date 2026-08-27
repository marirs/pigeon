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
//! This is the skeleton. Accepted mail is written to the spool directory and
//! goes no further: there is no routing table, no queue, and no onward
//! delivery. Configuration comes from the environment because the TOML loader
//! and SQLite schema arrive in Milestone 1.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pigeon_dns::{LookupError, MxLookup, SystemResolver, order_hosts};
use pigeon_smtp::{DataError, Envelope, Message, MessageSink, ServerConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// How long to wait for a receiving server to answer its door.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Deliveries attempted at once.
///
/// Inbound is capped too. Bounding one direction and not the other does not
/// make the process harder to exhaust — it only changes which resource runs
/// out first.
const MAX_CONCURRENT_DELIVERIES: usize = 32;

/// Where forwarded mail is sent, and who we claim to be when sending it.
#[derive(Clone)]
struct Forwarding {
    resolver: Arc<SystemResolver>,
    /// Name given in EHLO. Its forward and reverse DNS must agree with the
    /// sending address or receivers will treat everything as suspect.
    ehlo_name: String,
    destination: String,
    limit: Arc<Semaphore>,
}

/// Where mail lands, and what is allowed to arrive.
#[derive(Clone)]
struct SpoolSink {
    dir: Arc<PathBuf>,
    /// Recipients to accept. Empty means accept anything, which is only
    /// reasonable while there is no real routing table.
    accept: Arc<HashSet<String>>,
    counter: Arc<AtomicU64>,
    /// Distinguishes identifiers from different runs of the process.
    boot: u32,
    /// Absent means spool and stop, which is useful for testing the receiver
    /// without sending anything onward.
    forwarding: Option<Forwarding>,
}

impl MessageSink for SpoolSink {
    fn accepts_recipient(&self, address: &str) -> bool {
        self.accept.is_empty() || self.accept.contains(&address.to_ascii_lowercase())
    }

    async fn deliver(&self, message: Message) -> Result<String, DataError> {
        let id = self.next_id();
        let Message { envelope, received, body } = message;

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

                    // Acquired *before* spawning. Taking it inside the task
                    // bounds concurrent connections but not the number of
                    // pending tasks — each of which pins a whole message in
                    // memory. A sender looping 50 MB messages would grow the
                    // process without limit while 32 permits trickled through.
                    // Waiting here pushes backpressure into the SMTP session,
                    // which is what the inbound side already does.
                    let permit = match Arc::clone(&f.limit).acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            tracing::error!(%id, "delivery limiter closed; message left in spool");
                            return Ok(id);
                        }
                    };

                    tokio::spawn(async move {
                        let _permit = permit;

                        match forward(&f, rotation, &envelope, &received, &body).await {
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
                            Err(e) => tracing::error!(
                                id = %id2,
                                error = %e,
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

impl SpoolSink {
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
        write_durably(&self.dir, &format!("{id}.eml"), &[received.as_bytes(), body]).await?;
        sync_dir(&self.dir).await
    }
}

/// Count messages left in the spool from an earlier run.
async fn count_spooled(dir: &Path) -> io::Result<usize> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut n = 0;
    while let Some(e) = entries.next_entry().await? {
        if e.file_name().to_string_lossy().ends_with(".eml") {
            n += 1;
        }
    }
    Ok(n)
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
async fn forward(
    f: &Forwarding,
    rotation: u64,
    envelope: &Envelope,
    received: &str,
    body: &[u8],
) -> Result<String, String> {
    let domain = f
        .destination
        .rsplit_once('@')
        .map(|(_, d)| d)
        .ok_or_else(|| format!("destination {} has no domain", f.destination))?;

    let hosts = match f.resolver.lookup_mx(domain).await {
        Ok(records) => order_hosts(&records, rotation).map_err(|e| e.to_string())?,
        // A domain with no MX still accepts mail at its own address record.
        // This is the implicit MX rule, and skipping it loses mail to small
        // domains that never published one.
        Err(LookupError::NoRecords(_)) => vec![domain.to_string()],
        Err(e) => return Err(e.to_string()),
    };

    // The envelope Pigeon sends is its own: one recipient, the configured
    // destination. Rewriting the sender for SPF comes with SRS in Milestone 2.
    let outgoing = Envelope {
        sender: envelope.sender.clone(),
        recipients: vec![f.destination.clone()],
    };

    let mut last = String::from("no hosts tried");

    for host in &hosts {
        let connect = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), 25)));

        let stream = match connect.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                last = format!("{host}: {e}");
                tracing::warn!(%host, error = %e, "connect failed, trying next host");
                continue;
            }
            Err(_) => {
                last = format!("{host}: connect timed out");
                tracing::warn!(%host, "connect timed out, trying next host");
                continue;
            }
        };

        // Trace header first, then the body, as one stream — the receiver sees
        // one message and the body is never copied to prepend to it.
        match pigeon_smtp::deliver(stream, &f.ehlo_name, &outgoing, &[received.as_bytes(), body])
            .await
        {
            Ok(accepted) => return Ok(accepted.message),
            Err(e) if e.is_permanent() => return Err(format!("{host}: {e}")),
            Err(e) => {
                last = format!("{host}: {e}");
                tracing::warn!(%host, error = %e, "temporary failure, trying next host");
            }
        }
    }

    Err(last)
}

/// The null sender prints as `<>` rather than as nothing, so a bounce is
/// distinguishable from a truncated log line.
fn display_sender(envelope: &Envelope) -> &str {
    if envelope.sender.is_empty() { "<>" } else { envelope.sender.as_str() }
}

async fn write_durably(dir: &Path, name: &str, parts: &[&[u8]]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.partial"));
    let final_path = dir.join(name);

    // `create_new` rather than `create`: truncating an existing file here would
    // destroy a message that was already acknowledged and is still waiting for
    // a delivery that failed.
    let mut f = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .await?;
    for part in parts {
        f.write_all(part).await?;
    }
    f.sync_all().await?;
    drop(f);

    tokio::fs::rename(&tmp, &final_path).await
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
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let listen = env_or("PIGEON_LISTEN", "127.0.0.1:2525");
    let hostname = env_or("PIGEON_HOSTNAME", "localhost");
    let spool = PathBuf::from(env_or("PIGEON_SPOOL", "./spool"));

    let accept: HashSet<String> = env_or("PIGEON_ACCEPT", "")
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // An unusable spool is local, unambiguous misconfiguration, so it stops
    // startup rather than being discovered on the first message.
    tokio::fs::create_dir_all(&spool).await.map_err(|e| {
        io::Error::new(e.kind(), format!("spool directory {} is unusable: {e}", spool.display()))
    })?;
    let sink_dir = spool.clone();

    let listener = TcpListener::bind(&listen).await.map_err(|e| {
        io::Error::new(e.kind(), format!("cannot bind {listen}: {e}"))
    })?;

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
    match count_spooled(&sink_dir).await {
        Ok(0) => {}
        Ok(n) => tracing::warn!(
            stranded = n,
            path = %sink_dir.display(),
            "spool is not empty: these messages were acknowledged but never delivered, \
             and nothing will retry them. Inspect and resend or remove them."
        ),
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
