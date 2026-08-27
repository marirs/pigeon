//! Writes and reads against the control plane.
//!
//! Every function here takes a `&Connection` that the caller has already put
//! inside a transaction. None of them commits, and none of them decides whether
//! the result is a valid configuration — that is
//! `pigeon_route::Snapshot::build`, and it runs on the same transaction before
//! it commits (`M1-SCHEMA.md` S-2). A repository that validated as it wrote
//! would be a second, quieter place where routing rules live.
//!
//! What these do enforce is the shape of a row: parameterised queries only,
//! addresses parsed before they are stored, and case folded on exactly the
//! halves Pigeon is authoritative for.

use rusqlite::{Connection, OptionalExtension, params};

use crate::DbError;

/// A mailbox, as stored.
///
/// `local` keeps its case and `domain` is folded. RFC 5321 §2.4 reserves the
/// local part to the destination host, and folding it merges distinct
/// recipients — finding 12.
///
/// `Ord` is derived so a fan-out set can be sorted into a canonical order:
/// two files listing the same destinations differently must produce the same
/// configuration. It orders by local part then domain, which is arbitrary and
/// only ever used for that.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub local: String,
    pub domain: String,
}

impl Address {
    /// Parse and normalise, refusing anything that is not deliverable.
    pub fn parse(raw: &str) -> Result<Self, DbError> {
        let parsed = pigeon_types::Address::parse(raw)
            .map_err(|e| DbError::BadAddress(format!("{raw:?}: {e}")))?;
        Ok(Self {
            local: parsed.local().to_string(),
            domain: parsed.domain().to_ascii_lowercase(),
        })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// What an alias does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasKind {
    Forward,
    Reject,
}

impl AliasKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reject => "reject",
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ------------------------------------------------------------- destinations

/// Find or create the row for a mailbox, returning its id.
///
/// Shared rather than duplicated per use, which is what makes
/// `destination replace` a bounded foreign-key operation with an exact preview
/// rather than a text substitution across three tables (`M1-SCHEMA.md` §4).
pub fn intern_destination(conn: &Connection, address: &Address) -> Result<i64, DbError> {
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM destination WHERE local = ?1 AND domain = ?2",
            params![address.local, address.domain],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        return Ok(id);
    }
    conn.execute(
        "INSERT INTO destination (local, domain) VALUES (?1, ?2)",
        params![address.local, address.domain],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Delete destinations nothing refers to.
///
/// Every reference is `ON DELETE RESTRICT`, so a mailbox that is still routing
/// cannot be removed by accident; this is the only path that removes one, and
/// it only removes the unreferenced. Called after any mutation that may have
/// dropped the last reference.
pub fn prune_destinations(conn: &Connection) -> Result<usize, DbError> {
    Ok(conn.execute(
        "DELETE FROM destination WHERE id NOT IN (
             SELECT destination_id FROM alias_destination
             UNION SELECT default_destination_id FROM domain WHERE default_destination_id IS NOT NULL
             UNION SELECT catchall_destination_id FROM domain WHERE catchall_destination_id IS NOT NULL
             UNION SELECT notify_destination_id FROM domain WHERE notify_destination_id IS NOT NULL
         )",
        [],
    )?)
}

/// How a mailbox is used, for `pigeon destination list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationUse {
    pub address: Address,
    pub aliases: i64,
    pub domains: i64,
    pub default_for: i64,
}

pub fn list_destinations(conn: &Connection) -> Result<Vec<DestinationUse>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT d.local, d.domain,
                (SELECT count(*) FROM alias_destination ad WHERE ad.destination_id = d.id),
                (SELECT count(DISTINCT a.domain_id) FROM alias_destination ad
                    JOIN alias a ON a.id = ad.alias_id WHERE ad.destination_id = d.id),
                (SELECT count(*) FROM domain dom WHERE dom.default_destination_id = d.id)
         FROM destination d
         ORDER BY d.domain, d.local",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(DestinationUse {
            address: Address {
                local: r.get(0)?,
                domain: r.get(1)?,
            },
            aliases: r.get(2)?,
            domains: r.get(3)?,
            default_for: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Repoint every use of one mailbox at another.
///
/// Aliases, catch-all destinations and domain defaults, optionally narrowed to
/// one domain — which is why this repoints foreign keys rather than renaming
/// the row. Renaming would move every use everywhere, and `--domain` exists
/// precisely because that is not always what is wanted.
///
/// Returns how many references moved.
pub fn replace_destination(
    conn: &Connection,
    old: &Address,
    new: &Address,
    only_domain: Option<&str>,
) -> Result<usize, DbError> {
    let Some(old_id) = conn
        .query_row(
            "SELECT id FROM destination WHERE local = ?1 AND domain = ?2",
            params![old.local, old.domain],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    else {
        return Ok(0);
    };
    let new_id = intern_destination(conn, new)?;
    if new_id == old_id {
        return Ok(0);
    }

    let scope = only_domain.map(|d| d.to_ascii_lowercase());
    let mut moved = 0;

    // An alias may already point at the new mailbox, and the primary key would
    // refuse the duplicate. Dropping those first turns "already correct" into a
    // no-op instead of an error.
    moved += conn.execute(
        "DELETE FROM alias_destination
         WHERE destination_id = ?1
           AND alias_id IN (SELECT alias_id FROM alias_destination WHERE destination_id = ?2)
           AND alias_id IN (SELECT id FROM alias WHERE ?3 IS NULL OR domain_id =
                (SELECT id FROM domain WHERE name = ?3))",
        params![old_id, new_id, scope],
    )?;

    moved += conn.execute(
        "UPDATE alias_destination SET destination_id = ?2
         WHERE destination_id = ?1
           AND alias_id IN (SELECT id FROM alias WHERE ?3 IS NULL OR domain_id =
                (SELECT id FROM domain WHERE name = ?3))",
        params![old_id, new_id, scope],
    )?;

    moved += conn.execute(
        "UPDATE domain SET default_destination_id = ?2, updated_at = ?4
         WHERE default_destination_id = ?1 AND (?3 IS NULL OR name = ?3)",
        params![old_id, new_id, scope, now()],
    )?;

    moved += conn.execute(
        "UPDATE domain SET catchall_destination_id = ?2, updated_at = ?4
         WHERE catchall_destination_id = ?1 AND (?3 IS NULL OR name = ?3)",
        params![old_id, new_id, scope, now()],
    )?;

    prune_destinations(conn)?;
    Ok(moved)
}

// ------------------------------------------------------------------ domains

fn domain_id(conn: &Connection, name: &str) -> Result<i64, DbError> {
    conn.query_row(
        "SELECT id FROM domain WHERE name = ?1",
        [name.to_ascii_lowercase()],
        |r| r.get(0),
    )
    .optional()?
    .ok_or_else(|| DbError::NoSuchDomain(name.to_string()))
}

pub fn domain_exists(conn: &Connection, name: &str) -> Result<bool, DbError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM domain WHERE name = ?1",
            [name.to_ascii_lowercase()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Create a domain. It starts in `new` and carries no mail until DNS validation
/// moves it, which is Milestone 5.
pub fn add_domain(
    conn: &Connection,
    name: &str,
    default: Option<&Address>,
) -> Result<i64, DbError> {
    let name = name.to_ascii_lowercase();
    if domain_exists(conn, &name)? {
        return Err(DbError::DomainExists(name));
    }
    let default_id = default.map(|a| intern_destination(conn, a)).transpose()?;
    let t = now();
    conn.execute(
        "INSERT INTO domain (name, default_destination_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?3)",
        params![name, default_id, t],
    )?;
    Ok(conn.last_insert_rowid())
}

/// What removing a domain would destroy, for the confirmation prompt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalImpact {
    pub aliases: i64,
    pub catchall: Option<String>,
    pub sender_identities: i64,
    pub dkim_selectors: Vec<String>,
}

pub fn removal_impact(conn: &Connection, name: &str) -> Result<RemovalImpact, DbError> {
    let id = domain_id(conn, name)?;
    let aliases = conn.query_row(
        "SELECT count(*) FROM alias WHERE domain_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let catchall = conn
        .query_row(
            "SELECT d.local || '@' || d.domain FROM domain dom
             LEFT JOIN destination d ON d.id = coalesce(dom.catchall_destination_id,
                                                        dom.default_destination_id)
             WHERE dom.id = ?1 AND dom.catchall_enabled = 1",
            [id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    let sender_identities = conn.query_row(
        "SELECT count(*) FROM sender_identity WHERE domain_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let mut stmt = conn.prepare("SELECT selector FROM dkim_key WHERE domain_id = ?1")?;
    let dkim_selectors = stmt
        .query_map([id], |r| r.get::<_, String>(0))?
        .collect::<Result<_, _>>()?;

    Ok(RemovalImpact {
        aliases,
        catchall,
        sender_identities,
        dkim_selectors,
    })
}

/// Delete a domain and everything under it.
///
/// Aliases, identities and DKIM rows cascade. The DKIM *private key file* is
/// not touched here: it is the one piece of state no backup of this database
/// restores, and deleting it is a decision for the caller to make explicitly
/// rather than a side effect of a row disappearing.
pub fn remove_domain(conn: &Connection, name: &str) -> Result<(), DbError> {
    let id = domain_id(conn, name)?;
    conn.execute("DELETE FROM domain WHERE id = ?1", [id])?;
    prune_destinations(conn)?;
    Ok(())
}

/// Set or clear the destination aliases inherit.
pub fn set_default_destination(
    conn: &Connection,
    name: &str,
    to: Option<&Address>,
) -> Result<(), DbError> {
    let id = domain_id(conn, name)?;
    let dest_id = to.map(|a| intern_destination(conn, a)).transpose()?;
    conn.execute(
        "UPDATE domain SET default_destination_id = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, dest_id, now()],
    )?;
    prune_destinations(conn)?;
    Ok(())
}

/// Turn inbound mail for a domain on or off.
///
/// Administrative, and independent of `status`: a domain switched off is still
/// somewhere in its DNS lifecycle and returns exactly as it was.
pub fn set_inbound_enabled(conn: &Connection, name: &str, enabled: bool) -> Result<(), DbError> {
    let id = domain_id(conn, name)?;
    conn.execute(
        "UPDATE domain SET inbound_enabled = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, i64::from(enabled), now()],
    )?;
    Ok(())
}

pub fn set_plus_addressing(conn: &Connection, name: &str, on: bool) -> Result<(), DbError> {
    let id = domain_id(conn, name)?;
    conn.execute(
        "UPDATE domain SET plus_addressing = ?2, updated_at = ?3 WHERE id = ?1",
        params![id, i64::from(on), now()],
    )?;
    Ok(())
}

/// One row of `pigeon domains list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSummary {
    pub name: String,
    pub status: String,
    pub inbound_enabled: bool,
    pub outbound_enabled: bool,
    pub aliases: i64,
    pub catchall: bool,
    pub default_destination: Option<String>,
}

pub fn list_domains(conn: &Connection) -> Result<Vec<DomainSummary>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT d.name, d.status, d.inbound_enabled, d.outbound_enabled,
                (SELECT count(*) FROM alias a WHERE a.domain_id = d.id),
                d.catchall_enabled,
                dd.local || '@' || dd.domain
         FROM domain d
         LEFT JOIN destination dd ON dd.id = d.default_destination_id
         ORDER BY d.name",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(DomainSummary {
            name: r.get(0)?,
            status: r.get(1)?,
            inbound_enabled: r.get::<_, i64>(2)? != 0,
            outbound_enabled: r.get::<_, i64>(3)? != 0,
            aliases: r.get(4)?,
            catchall: r.get::<_, i64>(5)? != 0,
            default_destination: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

// ------------------------------------------------------------------ aliases

/// Add an alias.
///
/// An empty `to` on a forwarding alias means "inherit the domain default", and
/// the absence *is* the encoding — see `M1-SCHEMA.md` §4. Whether the domain
/// has a default to inherit is not checked here: that is a property of the
/// resulting configuration, and `Snapshot::build` decides it.
pub fn add_alias(
    conn: &Connection,
    domain: &str,
    pattern: &str,
    kind: AliasKind,
    to: &[Address],
) -> Result<i64, DbError> {
    let id = domain_id(conn, domain)?;
    let pattern = pattern.to_ascii_lowercase();

    if kind == AliasKind::Reject && !to.is_empty() {
        return Err(DbError::RejectWithDestinations(pattern));
    }

    conn.execute(
        "INSERT INTO alias (domain_id, pattern, kind, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, pattern, kind.as_str(), now()],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            DbError::AliasExists {
                domain: domain.to_string(),
                pattern: pattern.clone(),
            }
        }
        other => DbError::Sqlite(other),
    })?;
    let alias_id = conn.last_insert_rowid();

    for address in to {
        let dest_id = intern_destination(conn, address)?;
        conn.execute(
            "INSERT OR IGNORE INTO alias_destination (alias_id, destination_id) VALUES (?1, ?2)",
            params![alias_id, dest_id],
        )?;
    }
    Ok(alias_id)
}

/// Remove one alias. Returns whether there was one.
pub fn remove_alias(conn: &Connection, domain: &str, pattern: &str) -> Result<bool, DbError> {
    let id = domain_id(conn, domain)?;
    let n = conn.execute(
        "DELETE FROM alias WHERE domain_id = ?1 AND pattern = ?2",
        params![id, pattern.to_ascii_lowercase()],
    )?;
    prune_destinations(conn)?;
    Ok(n > 0)
}

/// Remove every alias on a domain. Returns how many.
pub fn remove_all_aliases(conn: &Connection, domain: &str) -> Result<usize, DbError> {
    let id = domain_id(conn, domain)?;
    let n = conn.execute("DELETE FROM alias WHERE domain_id = ?1", [id])?;
    prune_destinations(conn)?;
    Ok(n)
}

/// One row of `pigeon alias list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasSummary {
    pub pattern: String,
    pub reject: bool,
    /// Empty means it inherits the domain default.
    pub destinations: Vec<String>,
}

pub fn list_aliases(conn: &Connection, domain: &str) -> Result<Vec<AliasSummary>, DbError> {
    let id = domain_id(conn, domain)?;
    let mut stmt =
        conn.prepare("SELECT id, pattern, kind FROM alias WHERE domain_id = ?1 ORDER BY pattern")?;
    let rows: Vec<(i64, String, String)> = stmt
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (alias_id, pattern, kind) in rows {
        let mut d = conn.prepare(
            "SELECT dst.local || '@' || dst.domain
             FROM alias_destination ad JOIN destination dst ON dst.id = ad.destination_id
             WHERE ad.alias_id = ?1 ORDER BY dst.domain, dst.local",
        )?;
        let destinations = d
            .query_map([alias_id], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        out.push(AliasSummary {
            pattern,
            reject: kind != "forward",
            destinations,
        });
    }
    Ok(out)
}

// ----------------------------------------------------------------- catch-all

/// Enable catch-all, optionally with its own destination.
///
/// `None` inherits the domain default. Never enabled implicitly: this is the
/// only path that sets the flag.
pub fn set_catchall(conn: &Connection, domain: &str, to: Option<&Address>) -> Result<(), DbError> {
    let id = domain_id(conn, domain)?;
    let dest_id = to.map(|a| intern_destination(conn, a)).transpose()?;
    conn.execute(
        "UPDATE domain SET catchall_enabled = 1, catchall_destination_id = ?2, updated_at = ?3
         WHERE id = ?1",
        params![id, dest_id, now()],
    )
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // The schema refuses an enabled catch-all with no effective
            // destination, on this path as well as on insert.
            DbError::CatchAllNeedsDestination(domain.to_string())
        }
        other => DbError::Sqlite(other),
    })?;
    Ok(())
}

pub fn clear_catchall(conn: &Connection, domain: &str) -> Result<(), DbError> {
    let id = domain_id(conn, domain)?;
    // Both columns, in one statement: the schema refuses a destination on a
    // disabled catch-all, so clearing them separately would fail on the first.
    conn.execute(
        "UPDATE domain SET catchall_enabled = 0, catchall_destination_id = NULL, updated_at = ?2
         WHERE id = ?1",
        params![id, now()],
    )?;
    prune_destinations(conn)?;
    Ok(())
}

// ---------------------------------------------------------------- DKIM keys

/// A key's public half and where its private half lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKey {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub public_key: String,
    /// Relative to the configured keys root, which is what contains it.
    pub private_key_path: String,
    pub state: String,
}

/// Record a generated key.
///
/// The private key is **not** passed here and never enters the database. What
/// is stored is where to find it, and the public half needed to render the
/// record and to check the two still agree.
pub fn add_dkim_key(
    conn: &Connection,
    domain: &str,
    selector: &str,
    public_key: &str,
    private_key_path: &str,
) -> Result<i64, DbError> {
    let id = domain_id(conn, domain)?;
    conn.execute(
        "INSERT INTO dkim_key (domain_id, selector, algorithm, public_key,
                               private_key_path, state, created_at)
         VALUES (?1, ?2, 'rsa2048', ?3, ?4, 'active', ?5)",
        params![id, selector, public_key, private_key_path, now()],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Active keys, for the startup verification and for `dns show`.
pub fn active_dkim_keys(conn: &Connection) -> Result<Vec<DkimKey>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT d.name, k.selector, k.algorithm, k.public_key, k.private_key_path, k.state
         FROM dkim_key k JOIN domain d ON d.id = k.domain_id
         WHERE k.state = 'active'
         ORDER BY d.name, k.selector",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(DkimKey {
            domain: r.get(0)?,
            selector: r.get(1)?,
            algorithm: r.get(2)?,
            public_key: r.get(3)?,
            private_key_path: r.get(4)?,
            state: r.get(5)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// A domain's active keys.
pub fn dkim_keys_for(conn: &Connection, domain: &str) -> Result<Vec<DkimKey>, DbError> {
    Ok(active_dkim_keys(conn)?
        .into_iter()
        .filter(|k| k.domain == domain.to_ascii_lowercase())
        .collect())
}
