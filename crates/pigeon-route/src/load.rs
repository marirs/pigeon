//! Reading a configuration out of SQLite and into a snapshot.
//!
//! Deliberately dumb: this transcribes rows and decides nothing. Every rule
//! about what a valid configuration is lives in [`crate::snapshot::Snapshot::build`],
//! which is the enforcement boundary (`M1-SCHEMA.md` S-2). A loader that
//! filtered or corrected as it read would be a second, quieter place where
//! routing gets decided.
//!
//! It reads through a `&Connection`, so a caller inside a write transaction
//! passes that transaction and gets the state that is about to become real —
//! which is what makes a prospective snapshot prospective.

use rusqlite::Connection;

use crate::snapshot::{AliasInput, CatchAllInput, Destination, DomainInput};
use pigeon_types::{DomainGate, DomainStatus};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error(
        "domain {domain} has status {status:?}, which this build does not recognise. \
         It was written by a different version; guessing would either gate a live domain \
         or ungate a broken one."
    )]
    UnknownStatus { domain: String, status: String },
}

/// Read every domain and its rules.
pub fn load(conn: &Connection) -> Result<Vec<DomainInput>, LoadError> {
    let mut stmt = conn.prepare(
        "SELECT d.id, d.name, d.status, d.inbound_enabled, d.outbound_enabled,
                d.plus_addressing, d.catchall_enabled,
                dd.local, dd.domain,
                cd.local, cd.domain
         FROM domain d
         LEFT JOIN destination dd ON dd.id = d.default_destination_id
         LEFT JOIN destination cd ON cd.id = d.catchall_destination_id
         ORDER BY d.name",
    )?;

    let rows = stmt.query_map([], |r| {
        Ok(RawDomain {
            id: r.get(0)?,
            name: r.get(1)?,
            status: r.get(2)?,
            inbound_enabled: r.get::<_, i64>(3)? != 0,
            outbound_enabled: r.get::<_, i64>(4)? != 0,
            plus_addressing: r.get::<_, i64>(5)? != 0,
            catchall_enabled: r.get::<_, i64>(6)? != 0,
            default_destination: optional_destination(r, 7, 8)?,
            catchall_destination: optional_destination(r, 9, 10)?,
        })
    })?;

    let raws: Vec<RawDomain> = rows.collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(raws.len());

    for raw in raws {
        let status =
            DomainStatus::from_stored(&raw.status).ok_or_else(|| LoadError::UnknownStatus {
                domain: raw.name.clone(),
                status: raw.status.clone(),
            })?;

        let aliases = load_aliases(conn, raw.id)?;

        // `catchall_enabled` is the authority; the destination is optional and
        // `None` means it inherits. The schema already refuses an enabled
        // catch-all with no effective destination, on the UPDATE path too, but
        // the snapshot re-checks — that CHECK covers rows written through
        // SQLite, not a database restored from somewhere else.
        let catchall = raw.catchall_enabled.then(|| CatchAllInput {
            destination: raw.catchall_destination.map(|d| vec![d]),
        });

        out.push(DomainInput {
            name: raw.name,
            gate: DomainGate {
                status,
                inbound_enabled: raw.inbound_enabled,
                outbound_enabled: raw.outbound_enabled,
            },
            plus_addressing: raw.plus_addressing,
            default_destination: raw.default_destination,
            aliases,
            catchall,
        });
    }

    Ok(out)
}

struct RawDomain {
    id: i64,
    name: String,
    status: String,
    inbound_enabled: bool,
    outbound_enabled: bool,
    plus_addressing: bool,
    catchall_enabled: bool,
    default_destination: Option<Destination>,
    catchall_destination: Option<Destination>,
}

fn load_aliases(conn: &Connection, domain_id: i64) -> Result<Vec<AliasInput>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT a.id, a.pattern, a.kind FROM alias a WHERE a.domain_id = ?1 ORDER BY a.pattern",
    )?;
    let rows = stmt.query_map([domain_id], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;

    let mut aliases = Vec::new();
    for row in rows {
        let (id, pattern, kind) = row?;
        aliases.push(AliasInput {
            pattern,
            // Anything that is not the word `forward` is treated as a reject.
            // The schema constrains this column to two values, so the only way
            // here is a hand-edited row — and refusing mail is the recoverable
            // direction if one somehow arrives.
            reject: kind != "forward",
            destinations: load_destinations(conn, id)?,
        });
    }
    Ok(aliases)
}

fn load_destinations(
    conn: &Connection,
    alias_id: i64,
) -> Result<Vec<Destination>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT d.local, d.domain
         FROM alias_destination ad JOIN destination d ON d.id = ad.destination_id
         WHERE ad.alias_id = ?1
         ORDER BY d.domain, d.local",
    )?;
    let rows = stmt.query_map([alias_id], |r| {
        Ok(Destination {
            local: r.get(0)?,
            domain: r.get(1)?,
        })
    })?;
    rows.collect()
}

fn optional_destination(
    row: &rusqlite::Row<'_>,
    local: usize,
    domain: usize,
) -> Result<Option<Destination>, rusqlite::Error> {
    let local: Option<String> = row.get(local)?;
    let domain: Option<String> = row.get(domain)?;
    Ok(match (local, domain) {
        (Some(local), Some(domain)) => Some(Destination { local, domain }),
        _ => None,
    })
}
