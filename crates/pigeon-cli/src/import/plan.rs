//! Validating a parsed plan against what is already there, and deciding what
//! the import is allowed to remove.
//!
//! Design: `M1-IMPORT.md` §2 and §4. Read-only — nothing here writes, and
//! nothing here decides whether the *resulting* configuration is serveable.
//! That is `Snapshot::build`, inside the transaction.

use std::collections::BTreeMap;

use pigeon_db::repo;
use rusqlite::Connection;

use super::parse::{Conflict, ConflictKind, Plan, Rule};

/// What the import may remove.
///
/// There is no default. A file is a list of what should exist and says nothing
/// about what should stop existing, so inferring the destructive reading from
/// the input is how an import deletes the alias somebody added last week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Keep existing routing. An alias in both, differing, is a conflict.
    Merge,
    /// Remove aliases **and the catch-all** on the imported domains first.
    ///
    /// The domain default is preserved (I-1): a catch-all is routing, which the
    /// file expresses; a default is policy, which the file cannot set. Removing
    /// it would delete something the import has no way to put back.
    Replace,
}

/// What one already-present domain holds that `--replace` would remove.
///
/// The trigger for requiring the flag is *any* of this, not the alias count.
/// A domain with a catch-all and no aliases is exactly the case an
/// "existing aliases" test waves through, and `--replace` would then silently
/// remove the rule accepting every address on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingRouting {
    pub domain: String,
    pub aliases: usize,
    pub catchall: bool,
}

impl ExistingRouting {
    fn is_empty(&self) -> bool {
        self.aliases == 0 && !self.catchall
    }

    pub fn describe(&self) -> String {
        match (self.aliases, self.catchall) {
            (0, true) => format!("{}: a catch-all", self.domain),
            (n, false) => format!("{}: {n} alias(es)", self.domain),
            (n, true) => format!("{}: {n} alias(es) and a catch-all", self.domain),
        }
    }
}

/// A plan that has been checked against the database and is ready to apply.
#[derive(Debug)]
pub struct Prepared {
    pub plan: Plan,
    pub mode: Mode,
    /// Domains in the file that do not exist yet, and so need a key.
    pub new_domains: Vec<String>,
    /// Domains in the file that already exist.
    pub existing_domains: Vec<String>,
    /// Rules already present, identical, that the import will not touch.
    pub unchanged: usize,
    /// What `--replace` would remove, captured so the transaction can confirm
    /// it has not moved.
    pub scoped: Vec<ExistingRouting>,
}

/// Why a plan cannot be prepared.
#[derive(Debug)]
pub enum PrepareError {
    /// Conflicts against the file or the database.
    Conflicts(Vec<Conflict>),
    /// Existing routing, and no `--merge` or `--replace`.
    ModeRequired(Vec<ExistingRouting>),
    Db(pigeon_db::DbError),
}

impl From<pigeon_db::DbError> for PrepareError {
    fn from(e: pigeon_db::DbError) -> Self {
        Self::Db(e)
    }
}

/// Check a parsed plan against current state.
pub fn prepare(
    conn: &Connection,
    plan: Plan,
    mode: Option<Mode>,
) -> Result<Prepared, PrepareError> {
    let mut conflicts = Vec::new();
    let mut new_domains = Vec::new();
    let mut existing_domains = Vec::new();
    let mut scoped = Vec::new();
    let mut unchanged = 0usize;

    for (domain, rules) in &plan.domains {
        if !repo::domain_exists(conn, domain)? {
            new_domains.push(domain.clone());
            continue;
        }
        existing_domains.push(domain.clone());

        let existing = existing_routing(conn, domain)?;
        if !existing.is_empty() {
            scoped.push(existing);
        }

        // Under `--replace` the existing rules are removed first, so they
        // cannot conflict with anything. Only merge compares.
        if mode == Some(Mode::Merge) || mode.is_none() {
            compare_against_existing(conn, domain, rules, &mut conflicts, &mut unchanged)?;
        }
    }

    // The flag is required whenever anything in the replace scope exists — not
    // when aliases exist. See `ExistingRouting`.
    let Some(mode) = mode else {
        if !scoped.is_empty() {
            return Err(PrepareError::ModeRequired(scoped));
        }
        // Nothing to remove, so the distinction is empty and merge is not a
        // choice anyone is making.
        return finish(
            plan,
            Mode::Merge,
            new_domains,
            existing_domains,
            unchanged,
            scoped,
            conflicts,
        );
    };

    finish(
        plan,
        mode,
        new_domains,
        existing_domains,
        unchanged,
        scoped,
        conflicts,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    plan: Plan,
    mode: Mode,
    new_domains: Vec<String>,
    existing_domains: Vec<String>,
    unchanged: usize,
    scoped: Vec<ExistingRouting>,
    conflicts: Vec<Conflict>,
) -> Result<Prepared, PrepareError> {
    if !conflicts.is_empty() {
        return Err(PrepareError::Conflicts(conflicts));
    }
    Ok(Prepared {
        plan,
        mode,
        new_domains,
        existing_domains,
        unchanged,
        scoped,
    })
}

/// What a domain currently holds inside the replace scope.
pub fn existing_routing(
    conn: &Connection,
    domain: &str,
) -> Result<ExistingRouting, pigeon_db::DbError> {
    let aliases = repo::list_aliases(conn, domain)?.len();
    let catchall = repo::list_domains(conn)?
        .into_iter()
        .find(|d| d.name == domain.to_ascii_lowercase())
        .map(|d| d.catchall)
        .unwrap_or(false);
    Ok(ExistingRouting {
        domain: domain.to_ascii_lowercase(),
        aliases,
        catchall,
    })
}

/// Under merge, an alias present in both must agree.
fn compare_against_existing(
    conn: &Connection,
    domain: &str,
    rules: &BTreeMap<String, Rule>,
    conflicts: &mut Vec<Conflict>,
    unchanged: &mut usize,
) -> Result<(), pigeon_db::DbError> {
    let present: BTreeMap<String, repo::AliasSummary> = repo::list_aliases(conn, domain)?
        .into_iter()
        .map(|a| (a.pattern.clone(), a))
        .collect();

    for (pattern, rule) in rules {
        if rule.is_catchall() {
            continue;
        }
        let Some(existing) = present.get(pattern) else {
            continue;
        };

        let same_kind = existing.reject == rule.reject;
        let mut wanted: Vec<String> = rule.destinations.iter().map(ToString::to_string).collect();
        wanted.sort();
        let mut have = existing.destinations.clone();
        have.sort();

        if same_kind && wanted == have {
            // A re-run of an import that partly succeeded elsewhere. Reported
            // rather than refused.
            *unchanged += 1;
            continue;
        }

        conflicts.push(Conflict {
            row: rule.rows.first().copied().unwrap_or(0),
            address: format!("{pattern}@{domain}"),
            kind: ConflictKind::ExistingAliasDiffers,
            message: format!(
                "{pattern}@{domain} already forwards to {}; the file says {}. \
                 Use --replace to take the file's version, or correct the file.",
                if have.is_empty() {
                    if existing.reject {
                        "REJECT".to_string()
                    } else {
                        "the domain default".to_string()
                    }
                } else {
                    have.join(", ")
                },
                if wanted.is_empty() {
                    "REJECT".to_string()
                } else {
                    wanted.join(", ")
                }
            ),
        });
    }
    Ok(())
}
