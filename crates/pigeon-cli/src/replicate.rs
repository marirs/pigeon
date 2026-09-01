//! `pigeon config export|checksum`: keeping two nodes saying the same thing.
//!
//! A second Pigeon is a **shared-nothing** node: its own database, its own
//! spool, its own queue. Two MX records point at both, senders pick one, and
//! neither node knows what the other is doing. That is the whole availability
//! design, and it works because a forwarder holds no shared mutable state —
//! there are no mailboxes to keep in step, and a message belongs entirely to
//! the node that answered `250` for it.
//!
//! What *does* have to match is the read-mostly part: which domains are
//! carried, where their mail goes, and which keys sign it. A node whose routing
//! is behind refuses recipients the other accepts, which looks to a sender like
//! intermittent rejection and to an operator like nothing at all.
//!
//! # Export and apply, not replicate
//!
//! There is no replication protocol. The routing configuration is exported as
//! the same CSV `pigeon import` already reads, applied on the other node, and
//! compared with a checksum. Every part of that is a thing that already exists
//! and can be inspected by a person.
//!
//! A protocol would mean a listener, an authentication scheme and a conflict
//! rule for simultaneous edits — three new failure modes, on a host whose
//! configuration changes when somebody adds an alias. Copying a file and
//! comparing a checksum has one failure mode, and it is visible.
//!
//! # What the checksum covers, and what it cannot
//!
//! Domains, aliases, destinations and the active DKIM selectors: everything
//! that decides where mail goes and who signs it. It does **not** cover the
//! private keys, which are not in the database at all — two nodes with matching
//! checksums and different key files sign differently, and the DNS record
//! matches only one of them. Copy the keys directory with the configuration.

use std::io::Write;

/// `pigeon config export`.
///
/// Deterministic: the same configuration produces byte-identical output on both
/// nodes, so a diff means a real difference rather than a different row order.
pub fn export(
    conn: &rusqlite::Connection,
    to: Option<&std::path::Path>,
    json: bool,
) -> anyhow::Result<u8> {
    let text = render(conn)?;

    match to {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;

            if json {
                crate::json::ok(serde_json::json!({
                    "exported": path.display().to_string(),
                    "checksum": checksum(&text),
                }));
            } else {
                println!("Wrote {}.\n", path.display());
                println!("  Checksum  {}\n", checksum(&text));
                println!(
                    "Apply it on the other node, then compare:\n  \
                     pigeon import csv {} --replace\n  \
                     pigeon config checksum",
                    path.display()
                );
                println!(
                    "\nThis does not include the DKIM private keys. Two nodes with matching\n\
                     checksums and different key files sign differently, and the published\n\
                     record matches only one of them — copy the keys directory too."
                );
            }
        }
        None => print!("{text}"),
    }
    Ok(crate::exit::OK)
}

/// `pigeon config checksum`: one line to compare between nodes.
pub fn print_checksum(conn: &rusqlite::Connection, json: bool) -> anyhow::Result<u8> {
    let sum = checksum(&render(conn)?);

    if json {
        crate::json::ok(serde_json::json!({ "checksum": sum }));
    } else {
        println!("{sum}");
    }
    Ok(crate::exit::OK)
}

/// The exported form: the same CSV `pigeon import` reads.
///
/// One row per rule, sorted, so two nodes with the same routing produce the
/// same bytes. A format that needed its own importer would be a second parser
/// for a thing that already has one.
fn render(conn: &rusqlite::Connection) -> anyhow::Result<String> {
    let mut out = String::new();
    out.push_str("# pigeon configuration export\n");
    out.push_str("# address,destination\n");

    let mut rows: Vec<String> = Vec::new();

    for domain in pigeon_db::repo::list_domains(conn)? {
        // The domain default, written as the catch-all row `import` understands
        // for a domain with no aliases of its own.
        if let Some(default) = &domain.default_destination {
            rows.push(format!("*@{},{}", domain.name, default));
        }

        for alias in pigeon_db::repo::list_aliases(conn, &domain.name)? {
            let address = format!("{}@{}", alias.pattern, domain.name);
            if alias.reject {
                rows.push(format!("{address},reject"));
                continue;
            }
            if alias.destinations.is_empty() {
                // Inherits the domain default. Written explicitly so the
                // importing node does not have to infer it from an absence.
                rows.push(format!("{address},inherit"));
                continue;
            }
            for destination in &alias.destinations {
                rows.push(format!("{address},{destination}"));
            }
        }
    }

    rows.sort();
    for row in rows {
        out.push_str(&row);
        out.push('\n');
    }

    // The signing identities, as a comment block: they are not routing and
    // `import` ignores them, but a node whose selectors differ signs mail the
    // other node's DNS record cannot verify — which is exactly the drift this
    // export exists to make visible.
    let mut keys: Vec<String> = pigeon_db::repo::active_dkim_keys(conn)?
        .into_iter()
        .map(|k| format!("# dkim {} {} {}", k.domain, k.selector, k.algorithm))
        .collect();
    keys.sort();
    for key in keys {
        out.push_str(&key);
        out.push('\n');
    }

    Ok(out)
}

/// SHA-256 of the export, hex, short enough to read over a phone.
fn checksum(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    // Sixteen hex characters: enough that two different configurations
    // colliding is not something that happens, short enough that a person
    // compares them correctly.
    digest
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated() -> rusqlite::Connection {
        let dir = std::env::temp_dir().join(format!(
            "pigeon-replicate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&path).unwrap();
        pigeon_db::migrate(&mut conn, &path).unwrap();
        conn
    }

    #[test]
    fn an_export_is_deterministic() {
        // The whole point: two nodes with the same routing produce the same
        // bytes, so a diff means a real difference rather than a different row
        // order out of SQLite.
        let conn = migrated();
        let me = pigeon_db::repo::Address::parse("me@example.net").unwrap();
        pigeon_db::repo::add_domain(&conn, "example.com", Some(&me)).unwrap();
        pigeon_db::repo::add_alias(
            &conn,
            "example.com",
            "hello",
            pigeon_db::repo::AliasKind::Forward,
            &[],
        )
        .unwrap();

        let first = render(&conn).unwrap();
        let second = render(&conn).unwrap();
        assert_eq!(first, second);
        assert_eq!(checksum(&first), checksum(&second));
    }

    #[test]
    fn a_changed_rule_changes_the_checksum() {
        // Otherwise the comparison is decoration.
        let conn = migrated();
        let me = pigeon_db::repo::Address::parse("me@example.net").unwrap();
        pigeon_db::repo::add_domain(&conn, "example.com", Some(&me)).unwrap();
        let before = checksum(&render(&conn).unwrap());

        pigeon_db::repo::add_alias(
            &conn,
            "example.com",
            "hello",
            pigeon_db::repo::AliasKind::Forward,
            &[],
        )
        .unwrap();
        assert_ne!(before, checksum(&render(&conn).unwrap()));
    }

    #[test]
    fn a_rejecting_alias_survives_the_round_trip_as_a_rejection() {
        // A reject rule exported as an ordinary alias would quietly start
        // delivering on the other node — the one difference in this format that
        // changes what happens to somebody's mail.
        let conn = migrated();
        let me = pigeon_db::repo::Address::parse("me@example.net").unwrap();
        pigeon_db::repo::add_domain(&conn, "example.com", Some(&me)).unwrap();
        pigeon_db::repo::add_alias(
            &conn,
            "example.com",
            "nope",
            pigeon_db::repo::AliasKind::Reject,
            &[],
        )
        .unwrap();

        let text = render(&conn).unwrap();
        assert!(
            text.contains("nope@example.com,reject"),
            "a reject rule was not exported as one:\n{text}"
        );
    }

    #[test]
    fn the_signing_identities_are_visible_in_the_export() {
        // Not routing, and `import` ignores them — but a node whose selectors
        // differ signs mail the other node's DNS record cannot verify, which is
        // exactly the drift this is for.
        let conn = migrated();
        let me = pigeon_db::repo::Address::parse("me@example.net").unwrap();
        pigeon_db::repo::add_domain(&conn, "example.com", Some(&me)).unwrap();
        pigeon_db::repo::add_dkim_key(&conn, "example.com", "sel", "AAAA", "example.com/sel.key")
            .unwrap();

        let text = render(&conn).unwrap();
        assert!(text.contains("# dkim example.com sel rsa2048"), "{text}");
    }
}
