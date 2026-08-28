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
///
/// # Why this is a fingerprint and not a count
///
/// The first version captured the alias count and whether a catch-all existed.
/// That passes the post-lock re-check for a change it exists to catch:
///
/// ```text
/// plan captured:    2 aliases
/// meanwhile:        alias A removed, alias B added
/// re-check sees:    2 aliases -> unchanged
/// --replace then deletes B, which was never in front of the confirmation
/// ```
///
/// So the capture is the *content*: every alias with its kind and its sorted
/// destinations, plus the catch-all's **effective** destination — effective
/// because a catch-all inheriting the domain default changes meaning when the
/// default changes, without the catch-all row moving at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingRouting {
    pub domain: String,
    pub aliases: usize,
    pub catchall: bool,
    /// Canonical, sorted, and compared in full.
    fingerprint: Vec<String>,
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

    /// What changed between two captures, for the abort message.
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        for line in &self.fingerprint {
            if !other.fingerprint.contains(line) {
                out.push(format!("gone: {line}"));
            }
        }
        for line in &other.fingerprint {
            if !self.fingerprint.contains(line) {
                out.push(format!("new:  {line}"));
            }
        }
        out
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

impl Prepared {
    /// Aliases this import would create: not catch-alls, and not rules already
    /// present and identical.
    pub fn aliases_to_create(&self) -> usize {
        self.plan
            .domains
            .values()
            .flat_map(|rules| rules.values())
            .filter(|r| !r.is_catchall())
            .count()
            .saturating_sub(self.unchanged)
    }

    /// Catch-alls this import would set.
    pub fn catchalls_to_set(&self) -> usize {
        self.plan
            .domains
            .values()
            .flat_map(|rules| rules.values())
            .filter(|r| r.is_catchall())
            .count()
    }
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
    let name = domain.to_ascii_lowercase();
    let aliases = repo::list_aliases(conn, domain)?;

    let summary = repo::list_domains(conn)?
        .into_iter()
        .find(|d| d.name == name);
    let catchall = summary.as_ref().map(|d| d.catchall).unwrap_or(false);
    let default = summary.as_ref().and_then(|d| d.default_destination.clone());

    let mut fingerprint: Vec<String> = aliases
        .iter()
        .map(|a| {
            let mut dests = a.destinations.clone();
            dests.sort();
            format!(
                "alias {} {} -> {}",
                a.pattern,
                if a.reject { "reject" } else { "forward" },
                if dests.is_empty() {
                    // Inheriting, so the *effective* target moves when the
                    // domain default does — recorded, because that is a change
                    // to what the alias does.
                    format!("(default: {})", default.as_deref().unwrap_or("none"))
                } else {
                    dests.join(",")
                }
            )
        })
        .collect();

    if catchall {
        fingerprint.push(format!(
            "catchall -> {}",
            effective_catchall(conn, &name)?.unwrap_or_else(|| "none".into())
        ));
    }
    fingerprint.sort();

    Ok(ExistingRouting {
        domain: name,
        aliases: aliases.len(),
        catchall,
        fingerprint,
    })
}

/// Where a domain's catch-all actually sends mail.
///
/// Its own destination if it has one, otherwise the domain default it inherits.
/// Comparing the stored column alone would call two catch-alls identical while
/// they forward to different mailboxes.
pub fn effective_catchall(
    conn: &Connection,
    domain: &str,
) -> Result<Option<String>, pigeon_db::DbError> {
    let own: Option<String> = conn
        .query_row(
            "SELECT d.local || '@' || d.domain FROM domain dom
             JOIN destination d ON d.id = dom.catchall_destination_id
             WHERE dom.name = ?1 AND dom.catchall_enabled = 1",
            [domain.to_ascii_lowercase()],
            |r| r.get(0),
        )
        .ok();
    if own.is_some() {
        return Ok(own);
    }
    Ok(repo::list_domains(conn)?
        .into_iter()
        .find(|d| d.name == domain.to_ascii_lowercase() && d.catchall)
        .and_then(|d| d.default_destination))
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
            // Compared, not skipped. Skipping it here meant `apply` overwrote an
            // existing catch-all with the file's — under `--merge`, which is
            // the mode whose entire promise is that it changes nothing that is
            // already there.
            //
            // The comparison is against the *effective* destination, because a
            // catch-all inheriting the domain default and one naming the same
            // address explicitly send mail to the same place.
            let Some(current) = effective_catchall(conn, domain)? else {
                continue;
            };
            let wanted = rule
                .destinations
                .first()
                .map(ToString::to_string)
                .unwrap_or_else(|| {
                    // No destination in the file means it inherits, so the
                    // effective target is the domain default.
                    repo::list_domains(conn)
                        .ok()
                        .and_then(|ds| {
                            ds.into_iter()
                                .find(|d| d.name == domain.to_ascii_lowercase())
                                .and_then(|d| d.default_destination)
                        })
                        .unwrap_or_default()
                });

            if wanted == current {
                *unchanged += 1;
            } else {
                conflicts.push(Conflict {
                    row: rule.rows.first().copied().unwrap_or(0),
                    address: format!("*@{domain}"),
                    kind: ConflictKind::ExistingAliasDiffers,
                    message: format!(
                        "{domain} already has a catch-all forwarding to {current}; the file \
                         says {wanted}. Use --replace to take the file's version, or correct \
                         the file."
                    ),
                });
            }
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
