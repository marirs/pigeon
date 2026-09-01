//! `pigeon health`, `pigeon backup` and `pigeon verify`.
//!
//! The three questions an operator asks that are not about one message: is this
//! host working, can I get its state back if the disk dies, and is the state
//! still intact.

use std::path::Path;

/// `pigeon health`: one screen, and an exit code a monitor can branch on.
///
/// Deliberately *not* a request to the daemon. There is no control socket, and
/// a health command that needed one would report "unhealthy" when the socket
/// was the only broken thing. What it reads is the state the daemon and the CLI
/// share: the database, the spool and the clock.
pub fn health(conn: &rusqlite::Connection, spool: Option<&Path>, json: bool) -> anyhow::Result<u8> {
    let schema = pigeon_db::schema_version(conn).unwrap_or(0);

    let domains: i64 = conn.query_row("SELECT count(*) FROM domain", [], |r| r.get(0))?;
    let gated: i64 = conn.query_row(
        "SELECT count(*) FROM domain WHERE status = 'error'",
        [],
        |r| r.get(0),
    )?;

    let waiting: i64 = conn.query_row(
        "SELECT count(*) FROM delivery WHERE state IN ('queued','deferred','delivering')",
        [],
        |r| r.get(0),
    )?;
    let frozen: i64 = conn.query_row(
        "SELECT count(*) FROM delivery WHERE frozen_at IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    let owed: i64 = conn.query_row(
        "SELECT count(*) FROM delivery WHERE notification = 'owed'",
        [],
        |r| r.get(0),
    )?;

    // The oldest thing still waiting is the number that says whether the queue
    // is draining. A count alone cannot: a hundred messages that arrived a
    // minute ago is a busy host, and one message from four days ago is a
    // problem nobody has noticed.
    let oldest: Option<i64> = conn
        .query_row(
            "SELECT min(m.received_at) FROM delivery d JOIN message m ON m.id = d.message_id
              WHERE d.state IN ('queued','deferred','delivering')",
            [],
            |r| r.get(0),
        )
        .unwrap_or(None);
    let oldest_age = oldest.map(|at| crate::now() - at);

    let disk = spool.and_then(|p| free_space(p).ok());

    // What makes this non-zero is deliberately narrow: a gated domain, or a
    // queue that is not draining. A busy queue is not a fault, and a health
    // check that pages on volume is one people turn off.
    let unhealthy = gated > 0 || oldest_age.is_some_and(|age| age > 24 * 3600);

    if json {
        crate::json::ok(serde_json::json!({
            "healthy": !unhealthy,
            "schema_version": schema,
            "domains": { "total": domains, "gated": gated },
            "queue": {
                "waiting": waiting,
                "frozen": frozen,
                "reports_owed": owed,
                "oldest_seconds": oldest_age,
            },
            "spool_free_bytes": disk,
        }));
        return Ok(verdict(unhealthy));
    }

    println!("Schema     v{schema}");
    println!("Domains    {domains} ({gated} gated)");
    println!("Queue      {waiting} waiting, {frozen} frozen, {owed} reports owed");
    match oldest_age {
        Some(age) => println!("Oldest     {}", duration(age)),
        None => println!("Oldest     nothing waiting"),
    }
    if let Some(free) = disk {
        println!("Spool disk {} free", bytes(free));
    }

    if unhealthy {
        println!("\nSomething needs attention:");
        if gated > 0 {
            println!("  {gated} domains are gated — pigeon domains check");
        }
        if let Some(age) = oldest_age.filter(|a| *a > 24 * 3600) {
            println!(
                "  mail has been waiting {} — pigeon queue list",
                duration(age)
            );
        }
    }
    Ok(verdict(unhealthy))
}

fn verdict(unhealthy: bool) -> u8 {
    if unhealthy {
        crate::exit::FAILED
    } else {
        crate::exit::OK
    }
}

/// `pigeon backup`: a consistent copy of the database, taken while it is in use.
///
/// SQLite's own backup API rather than copying the file: a copy taken with
/// `cp` while the daemon is writing can be torn across a WAL checkpoint, and
/// the result is a file that opens and then fails on the one page that matters.
///
/// **The DKIM private keys are not in here.** They are the only state no backup
/// of the database restores, and losing them means republishing DNS for every
/// domain by hand — so the command says so rather than letting an operator
/// discover it during a restore.
pub fn backup(
    conn: &rusqlite::Connection,
    to: &Path,
    keys: Option<&Path>,
    json: bool,
) -> anyhow::Result<u8> {
    if to.exists() {
        anyhow::bail!(
            "{} already exists.\n\n  \
             It was not overwritten: a backup that silently replaces the previous \n  \
             one leaves you with a single copy of whatever went wrong.",
            to.display()
        );
    }

    let mut destination = rusqlite::Connection::open(to)?;
    let backup = rusqlite::backup::Backup::new(conn, &mut destination)?;
    backup.run_to_completion(64, std::time::Duration::from_millis(10), None)?;
    drop(backup);

    // Checked immediately, because a backup nobody has read is a hope. This is
    // the same check `pigeon verify` runs, done here so the file is known good
    // at the moment it is written rather than at the moment it is needed.
    let ok: String = destination.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    drop(destination);

    if ok != "ok" {
        let _ = std::fs::remove_file(to);
        anyhow::bail!("the backup failed its integrity check and was removed: {ok}");
    }

    let size = std::fs::metadata(to).map(|m| m.len()).unwrap_or(0);

    if json {
        crate::json::ok(serde_json::json!({
            "backup": to.display().to_string(),
            "bytes": size,
            "keys_included": false,
            "keys_directory": keys.map(|p| p.display().to_string()),
        }));
    } else {
        println!("Wrote {} ({}).\n", to.display(), bytes(size));
        match keys {
            Some(dir) => println!(
                "This does not include the DKIM private keys in {}.\n\
                 They are the only state no backup of the database restores: without\n\
                 them every domain needs a new key and a new DNS record. Copy that\n\
                 directory too, and keep it somewhere the database backup is not.",
                dir.display()
            ),
            None => println!(
                "This does not include the DKIM private keys. They are the only state\n\
                 no backup of the database restores — copy the keys directory too."
            ),
        }
    }
    Ok(crate::exit::OK)
}

/// `pigeon verify`: is this database intact, and is it one Pigeon can open?
///
/// Both halves, because they fail differently. A corrupt page is a disk
/// problem; a schema from a newer build is a downgrade, and an operator
/// restoring a backup onto an older binary needs to be told which.
pub fn verify(path: &Path, json: bool) -> anyhow::Result<u8> {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;

    // `integrity_check` rather than `quick_check`: this is run on a backup
    // before trusting it, which is exactly when the extra pass is worth it.
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    let foreign_keys: i64 = conn
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .unwrap_or(0);

    let schema = pigeon_db::schema_version(&conn).unwrap_or(0);
    let expected = pigeon_db::migrate::latest_version();

    let intact = integrity == "ok" && foreign_keys == 0;
    let usable = schema <= expected;

    if json {
        crate::json::ok(serde_json::json!({
            "intact": intact,
            "integrity": integrity,
            "dangling_references": foreign_keys,
            "schema_version": schema,
            "supported_version": expected,
            "usable": usable,
        }));
        return Ok(verdict(!(intact && usable)));
    }

    println!("{}\n", path.display());
    println!("  Integrity  {integrity}");
    println!(
        "  References {}",
        if foreign_keys == 0 {
            "consistent".to_string()
        } else {
            format!("{foreign_keys} dangling")
        }
    );
    println!("  Schema     v{schema} (this build supports v{expected})");

    if !intact {
        println!("\nThis database is damaged. Restore from a backup rather than repairing it:");
        println!(
            "  a partially readable mail queue delivers some messages twice and loses others."
        );
    } else if !usable {
        println!(
            "\nThis database was written by a newer build. Migrations only run forwards,\n\
             so an older binary cannot open it — install the newer one."
        );
    }
    Ok(verdict(!(intact && usable)))
}

/// Free bytes on the filesystem holding `path`.
#[cfg(unix)]
fn free_space(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // SAFETY: `statvfs` writes into the struct and reads a NUL-terminated
    // path; both are satisfied here, and the result is checked.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(not(unix))]
fn free_space(_path: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "free space is only read on unix",
    ))
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn duration(seconds: i64) -> String {
    match seconds {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d {}h", s / 86_400, (s % 86_400) / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_ages_read_like_an_operator_expects() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KiB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MiB");

        assert_eq!(duration(30), "30s");
        assert_eq!(duration(150), "2m");
        assert_eq!(duration(7300), "2h 1m");
        assert_eq!(duration(200_000), "2d 7h");
    }
}
