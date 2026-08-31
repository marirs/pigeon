//! `pigeon srs keys` and `pigeon srs rotate`.
//!
//! The ring signs the return paths that let bounces find their way back, and it
//! is the one piece of state whose loss is invisible until somebody's mail
//! bounces and the bounce cannot be routed. So both commands are conservative:
//! rotation adds a key and never removes one, and every deletion date is
//! printed rather than acted on.

use std::io::Write;
use std::path::{Path, PathBuf};

use pigeon_auth::srs::{Day, KeyRing, MAX_KEYS, RETIREMENT_DAYS, Srs};
use serde_json::json;

use crate::json;

/// Read the ring and report it.
pub fn keys(path: &Path, as_json: bool) -> anyhow::Result<u8> {
    let ring = KeyRing::load(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let today = Day::now();

    if as_json {
        let keys: Vec<_> = ring
            .keys()
            .iter()
            .enumerate()
            .map(|(i, k)| {
                json!({
                    "id": k.id,
                    // Position, not identity: the first entry signs. Stated so a
                    // consumer does not have to infer it from the dates, which
                    // are documentation and deliberately not load-bearing.
                    "signing": i == 0,
                    "created": k.created,
                    "stopped_signing_at": k.stopped_signing_at,
                    // Null for the key that still signs: it has no deletion
                    // date because it has not stopped signing, which is a fact
                    // rather than a missing field. `--json` says null; the
                    // human form says nothing at all.
                    "may_be_deleted_after": deletion_date(k.stopped_signing_at.as_deref()),
                    "deletable_now": deletion_date(k.stopped_signing_at.as_deref())
                        .map(|_| is_deletable(k.stopped_signing_at.as_deref(), today)),
                })
            })
            .collect();
        json::ok(json!({ "path": path.display().to_string(), "keys": keys }));
        return Ok(crate::exit::OK);
    }

    println!("{}", path.display());
    for (i, key) in ring.keys().iter().enumerate() {
        let role = if i == 0 { "signs" } else { "verifies only" };
        match (
            &key.stopped_signing_at,
            deletion_date(key.stopped_signing_at.as_deref()),
        ) {
            (Some(stopped), Some(eligible)) => {
                let state = if is_deletable(key.stopped_signing_at.as_deref(), today) {
                    "may be deleted"
                } else {
                    "keep until"
                };
                println!(
                    "  {:>3}  {role:<14}  created {}  stopped signing {stopped}  {state} {eligible}",
                    key.id, key.created
                );
            }
            (Some(stopped), None) => println!(
                "  {:>3}  {role:<14}  created {}  stopped signing {stopped}  (unparsable date)",
                key.id, key.created
            ),
            _ => println!("  {:>3}  {role:<14}  created {}", key.id, key.created),
        }
    }
    println!(
        "\n  A displaced key must stay in the ring for {RETIREMENT_DAYS} days after it stops \n  \
         signing. Deleting it earlier breaks bounces for mail already in flight, and \n  \
         breaks them silently: the failure appears at somebody else's MTA."
    );
    Ok(crate::exit::OK)
}

/// Add a new signing key, keeping every existing one for verification.
pub fn rotate(path: &Path, as_json: bool) -> anyhow::Result<u8> {
    let ring = KeyRing::load(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;

    // Refused rather than silently dropping the oldest. Every key in the ring
    // is one HMAC per verification, which is attacker-triggered work — and the
    // key that would be dropped is precisely the one whose addresses are
    // closest to expiring, so dropping it is the operation most likely to
    // break a bounce.
    if ring.keys().len() >= MAX_KEYS {
        anyhow::bail!(
            "the ring already holds {} keys, which is the maximum\n\n  \
             Every verification tries each key in turn, so the ring is bounded.\n  \
             Remove a key that stopped signing more than {RETIREMENT_DAYS} days ago —\n  \
             `pigeon srs keys` shows when each became eligible — and rotate again.",
            ring.keys().len()
        );
    }

    let today = Day::now();
    let now = rfc3339_utc();
    let next_id = ring.keys().iter().map(|k| k.id).max().unwrap_or(0) + 1;
    let secret = generate_secret()?;

    // The new key first, so it signs; every existing key is kept, with the one
    // that was signing marked as having stopped now.
    let mut out = String::new();
    out.push_str("# id  created              stopped_signing_at   secret (base64, 32 bytes)\n");
    out.push_str(&format!(
        "{next_id}  {now}  -                    {secret}\n"
    ));
    for (i, key) in ring.keys().iter().enumerate() {
        let stopped = match (i, &key.stopped_signing_at) {
            (0, None) => now.clone(),
            (_, Some(existing)) => existing.clone(),
            // A key that was already verify-only and somehow carries no date.
            // Recorded as of now rather than left blank, since the whole point
            // of the field is that deletion eligibility can be computed.
            (_, None) => now.clone(),
        };
        out.push_str(&format!(
            "{}  {}  {stopped}  {}\n",
            key.id,
            key.created,
            key.secret_base64()
        ));
    }

    replace_durably(path, &out)?;

    // The displaced key's own deletion date, computed the same way `keys`
    // renders it, so the two commands cannot disagree.
    let eligible = render_day(i64::from(Srs::earliest_deletion(today).0));
    if as_json {
        json::ok(json!({
            "path": path.display().to_string(),
            "signing_key_id": next_id,
            "keys": ring.keys().len() + 1,
            // Days rather than a date: the ring records days, and rendering a
            // calendar date here would invent a precision the format does not
            // have.
            "displaced_key_deletable_after": eligible,
            "retention_days": RETIREMENT_DAYS,
        }));
    } else {
        println!(
            "Rotated. Key {next_id} now signs; {} kept for verification.",
            ring.keys().len()
        );
        println!("  The key it displaced may be deleted after {eligible}.");
        println!(
            "\n  Nothing was deleted. The key it displaced must stay for {RETIREMENT_DAYS} days —\n  \
             addresses it signed are still arriving, and a bounce is often the last\n  \
             thing to come back."
        );
    }
    Ok(crate::exit::OK)
}

/// The date a key that stopped signing on `stopped` becomes safe to delete.
///
/// `None` for a key that still signs, and for a date this cannot read — the
/// ring's dates are operator-edited, and an unparsable one is reported rather
/// than turned into a confident answer that happens to be wrong.
fn deletion_date(stopped: Option<&str>) -> Option<String> {
    let day = parse_day(stopped?)?;
    Some(render_day(day + i64::from(RETIREMENT_DAYS)))
}

fn is_deletable(stopped: Option<&str>, today: Day) -> bool {
    match stopped.and_then(parse_day) {
        Some(day) => i64::from(today.0) >= day + i64::from(RETIREMENT_DAYS),
        None => false,
    }
}

/// The date part of an RFC 3339 timestamp, as days since the epoch.
fn parse_day(timestamp: &str) -> Option<i64> {
    let date = timestamp.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(pigeon_types::days_from_civil(year, month, day))
}

fn render_day(day: i64) -> String {
    pigeon_types::rfc3339_utc(day * 86_400)
        .split('T')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// 32 bytes from the OS, base64-encoded.
fn generate_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("cannot read the system RNG: {e}"))?;
    Ok(base64_encode(&bytes))
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A UTC timestamp for the `created` column.
fn rfc3339_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    pigeon_types::rfc3339_utc(secs)
}

/// Replace the ring atomically and durably, under an exclusive lock.
///
/// Three separate problems, and skipping any one of them loses keys:
///
/// - **Concurrency.** Two rotations racing would each read the ring, add a key
///   and write, and the second write would silently drop the first's key —
///   along with every address it had already signed. The lock is a file created
///   with `O_EXCL`, which is atomic on every filesystem this runs on.
/// - **Atomicity.** A partial write leaves a ring that will not parse, and the
///   daemon's reconciliation would refuse it — correctly, but the operator
///   would be left with no way to sign. The new content goes to a temporary
///   file and is renamed over the old one, which is atomic.
/// - **Durability.** Content in the page cache and a directory entry that
///   survives are two different things, so both are fsynced. A ring that
///   "rotated" and did not survive the reboot is the worst of both: the
///   operator believes the old key was displaced.
fn replace_durably(path: &Path, content: &str) -> anyhow::Result<()> {
    let lock = LockFile::acquire(path)?;

    let tmp = temp_beside(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600 from the moment it exists, not after: a ring readable for even
        // an instant is a ring that was readable.
        options.mode(0o600);
    }

    let written = (|| -> std::io::Result<()> {
        let mut f = options.open(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()
    })();

    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        drop(lock);
        anyhow::bail!("cannot write {}: {e}", tmp.display());
    }

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        drop(lock);
        anyhow::bail!("cannot replace {}: {e}", path.display());
    }

    // The rename is durable only once the directory is.
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::File::open(dir).and_then(|d| d.sync_all())
    {
        drop(lock);
        anyhow::bail!("cannot flush {}: {e}", dir.display());
    }

    Ok(())
}

fn temp_beside(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".rotate.{}", std::process::id()));
    path.with_file_name(name)
}

/// An exclusive lock held for the length of a rotation.
struct LockFile(PathBuf);

impl LockFile {
    fn acquire(path: &Path) -> anyhow::Result<Self> {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        let lock = path.with_file_name(name);

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(_) => Ok(Self(lock)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => anyhow::bail!(
                "another rotation is in progress ({} exists)\n\n  \
                 If no other `pigeon srs rotate` is running, a previous one was \n  \
                 interrupted. The ring itself is untouched — remove the lock file \n  \
                 and try again.",
                lock.display()
            ),
            Err(e) => anyhow::bail!("cannot lock {}: {e}", lock.display()),
        }
    }
}

impl Drop for LockFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
