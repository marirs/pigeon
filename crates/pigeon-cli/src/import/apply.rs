//! Writing an import: keys, then rows, then one commit.
//!
//! Design: `M1-IMPORT.md` §1. The ordering is the contract, and every step of
//! it is here rather than spread across the command, so a reader can check the
//! two against each other.

use std::path::{Path, PathBuf};

use pigeon_db::repo::{self, AliasKind};
use rusqlite::{Connection, TransactionBehavior};

use super::parse::{Conflict, ConflictKind};
use super::plan::{Mode, Prepared, existing_routing};

/// What an import did.
#[derive(Debug, Default)]
pub struct Applied {
    pub domains_created: usize,
    pub domains_matched: usize,
    pub aliases_created: usize,
    pub aliases_replaced: usize,
    pub catchalls_set: usize,
    pub keys_generated: usize,
    pub unchanged: usize,
}

#[derive(Debug)]
pub enum ApplyError {
    Conflicts(Vec<Conflict>),
    Db(pigeon_db::DbError),
    Route(pigeon_route::BuildError),
    Load(pigeon_route::LoadError),
    Sqlite(rusqlite::Error),
    Dkim(pigeon_auth::DkimError),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A failure, plus key files this run wrote and could not remove.
    ///
    /// They are inert — nothing references them and no later run reuses their
    /// names — but they are private key material a failed command left behind,
    /// so they are named rather than left to be found with `ls`.
    WithOrphans {
        source: Box<ApplyError>,
        orphaned: Vec<PathBuf>,
    },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflicts(c) => write!(f, "{} conflict(s)", c.len()),
            Self::Db(e) => write!(f, "{e}"),
            Self::Route(e) => write!(f, "{e}"),
            Self::Load(e) => write!(f, "{e}"),
            Self::Sqlite(e) => write!(f, "{e}"),
            Self::Dkim(e) => write!(f, "{e}"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::WithOrphans { source, orphaned } => {
                write!(f, "{source}\n\n  Key files this run could not remove:")?;
                for p in orphaned {
                    write!(f, "\n    {}", p.display())?;
                }
                write!(
                    f,
                    "\n\n  Nothing references them. Remove them once you are satisfied \
                     no other import is running."
                )
            }
        }
    }
}

impl std::error::Error for ApplyError {}

macro_rules! from_error {
    ($t:ty, $v:ident) => {
        impl From<$t> for ApplyError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from_error!(pigeon_db::DbError, Db);
from_error!(pigeon_route::BuildError, Route);
from_error!(pigeon_route::LoadError, Load);
from_error!(rusqlite::Error, Sqlite);
from_error!(pigeon_auth::DkimError, Dkim);

/// A key generated for a new domain, held until the transaction commits.
struct PreparedKey {
    domain: String,
    selector: &'static str,
    file: String,
    path: PathBuf,
    public: String,
}

/// Steps 4 to 7.
///
/// `nonce` names key files; it is passed in so the caller owns the source of
/// randomness rather than this module reaching for one.
pub fn apply(
    conn: &mut Connection,
    keys_root: &Path,
    prepared: &Prepared,
    nonce: &dyn Fn() -> String,
) -> Result<Applied, ApplyError> {
    // ---- step 4: keys, durable, before the transaction ----
    //
    // A row may only ever name a key that is already on disk. The reverse order
    // turns any write or fsync failure into committed domains with no usable
    // key — and at import scale that is forty domains rather than one.
    let mut written: Vec<PreparedKey> = Vec::new();
    let outcome = prepare_keys(keys_root, prepared, nonce, &mut written)
        .and_then(|()| write_rows(conn, prepared, &written));

    match outcome {
        Ok(mut applied) => {
            applied.keys_generated = written.len();
            Ok(applied)
        }
        Err(e) => {
            // Every returned error removes the keys this run wrote. A key
            // belonging to no domain is private key material left behind by a
            // failed command.
            //
            // An earlier version computed the failures and threw them away, so
            // `orphaned_keys` could only ever be empty — the field existed and
            // reported nothing.
            let orphaned = remove_keys(&written);
            if orphaned.is_empty() {
                Err(e)
            } else {
                Err(ApplyError::WithOrphans {
                    source: Box::new(e),
                    orphaned,
                })
            }
        }
    }
}

/// Generate and durably write one key per new domain.
fn prepare_keys(
    keys_root: &Path,
    prepared: &Prepared,
    nonce: &dyn Fn() -> String,
    written: &mut Vec<PreparedKey>,
) -> Result<(), ApplyError> {
    let selector = pigeon_auth::dkim::DEFAULT_SELECTOR;

    for domain in &prepared.new_domains {
        let pair = pigeon_auth::KeyPair::generate(pigeon_auth::dkim::DEFAULT_BITS)?;
        let file = format!("{domain}.{selector}.{}.key", nonce());
        let path = keys_root.join(&file);

        crate::write_private_key(&path, pair.private_pem()).map_err(|e| ApplyError::Io {
            path: path.clone(),
            source: std::io::Error::other(e.to_string()),
        })?;

        written.push(PreparedKey {
            domain: domain.clone(),
            selector,
            file,
            path,
            public: pair.public_base64().to_string(),
        });
    }
    Ok(())
}

/// Steps 5 and 6.
fn write_rows(
    conn: &mut Connection,
    prepared: &Prepared,
    keys: &[PreparedKey],
) -> Result<Applied, ApplyError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // The only check driven by elapsed time rather than by the input.
    //
    // Key generation takes about a minute for forty domains, and the operator
    // confirmed `--replace` before it started. In that minute somebody can add
    // an alias to a domain in the file, and `--replace` would delete routing
    // that was never in front of the confirmation.
    recheck_plan(&tx, prepared)?;

    let mut applied = Applied {
        domains_matched: prepared.existing_domains.len(),
        unchanged: prepared.unchanged,
        ..Applied::default()
    };

    for key in keys {
        // Created exactly as `domain add` creates one: no default destination,
        // no lifecycle shortcut. The file cannot set policy.
        repo::add_domain(&tx, &key.domain, None)?;
        repo::add_dkim_key(&tx, &key.domain, key.selector, &key.public, &key.file)?;
        applied.domains_created += 1;
    }

    for (domain, rules) in &prepared.plan.domains {
        if prepared.mode == Mode::Replace && prepared.existing_domains.contains(domain) {
            // Aliases and the catch-all; the domain default is preserved (I-1).
            applied.aliases_replaced += repo::remove_all_aliases(&tx, domain)?;
            repo::clear_catchall(&tx, domain)?;
        }

        for rule in rules.values() {
            if rule.is_catchall() {
                // Under merge an identical catch-all is left alone. Preparation
                // has already refused a differing one, so reaching here with a
                // catch-all already present means it matches — and rewriting it
                // would be a write `--merge` promised not to make.
                if prepared.mode == Mode::Merge
                    && crate::import::plan::effective_catchall(&tx, domain)?.is_some()
                {
                    continue;
                }
                repo::set_catchall(&tx, domain, rule.destinations.first())?;
                applied.catchalls_set += 1;
                continue;
            }

            // Under merge, an identical alias is left alone rather than
            // re-created — `unchanged`, counted during preparation.
            if prepared.mode == Mode::Merge && already_identical(&tx, domain, rule)? {
                continue;
            }

            let kind = if rule.reject {
                AliasKind::Reject
            } else {
                AliasKind::Forward
            };
            repo::add_alias(&tx, domain, &rule.pattern, kind, &rule.destinations)?;
            applied.aliases_created += 1;
        }
    }

    // The whole point of the boundary: interactions *between* imported rows
    // that no row-level check can see. Two individually valid rows can be one
    // loop, and only a snapshot built from both finds it.
    //
    // Reported as a conflict rather than as a bare error, so an import failure
    // has one shape whether it came from the file or from the configuration the
    // file would produce. A consumer parsing `conflicts` should not need a
    // second path for the most interesting kind.
    if let Err(e) = pigeon_route::Snapshot::build(pigeon_route::load(&tx)?) {
        return Err(ApplyError::Conflicts(vec![Conflict {
            row: 0,
            address: String::new(),
            kind: ConflictKind::Unserveable,
            message: format!("{e}"),
        }]));
    }

    // Step 6, and the point of no return.
    tx.commit()?;

    // Step 7 — publication — is **not** done here, and deliberately not.
    //
    // The snapshot was built above to validate the change, then dropped. The
    // CLI is a separate process from the daemon: a router it published would
    // serve nothing and be freed when the command exits, which is a throwaway
    // that reads like publication and is not.
    //
    // So the commit completes the CLI's operation. Making the running daemon
    // pick the change up is the live-reload contract, which is the daemon's
    // side of this boundary: it detects the commit and publishes its own
    // snapshot, on its own connection.
    Ok(applied)
}

/// Require the replace scope to be exactly what was planned.
fn recheck_plan(conn: &Connection, prepared: &Prepared) -> Result<(), ApplyError> {
    let mut changed = Vec::new();

    for planned in &prepared.scoped {
        let now = existing_routing(conn, &planned.domain)?;
        if &now != planned {
            changed.push(Conflict {
                row: 0,
                address: planned.domain.clone(),
                kind: ConflictKind::StateChanged,
                message: format!(
                    "{} changed while this import was preparing. Nothing was imported. \
                     Re-run to see the current state before confirming.\n{}",
                    planned.domain,
                    planned
                        .differences(&now)
                        .iter()
                        .map(|d| format!("\n      {d}"))
                        .collect::<String>()
                ),
            });
        }
    }

    // A domain that did not exist when the plan was made but does now: its key
    // is already written and `add_domain` would refuse, but the message should
    // say why rather than reporting a duplicate.
    for domain in &prepared.new_domains {
        if repo::domain_exists(conn, domain)? {
            changed.push(Conflict {
                row: 0,
                address: domain.clone(),
                kind: ConflictKind::StateChanged,
                message: format!(
                    "{domain} was created while this import was preparing. Nothing was \
                     imported."
                ),
            });
        }
    }

    if changed.is_empty() {
        Ok(())
    } else {
        Err(ApplyError::Conflicts(changed))
    }
}

fn already_identical(
    conn: &Connection,
    domain: &str,
    rule: &super::parse::Rule,
) -> Result<bool, pigeon_db::DbError> {
    let Some(existing) = repo::list_aliases(conn, domain)?
        .into_iter()
        .find(|a| a.pattern == rule.pattern)
    else {
        return Ok(false);
    };
    if existing.reject != rule.reject {
        return Ok(false);
    }
    let mut wanted: Vec<String> = rule.destinations.iter().map(ToString::to_string).collect();
    wanted.sort();
    let mut have = existing.destinations;
    have.sort();
    Ok(wanted == have)
}

/// Remove keys this run wrote. Returns the ones that could not be removed.
///
/// The directory is flushed after a successful removal, so the *absence* is as
/// durable as the file was — a crash immediately after cleanup must not bring
/// the key back.
fn remove_keys(written: &[PreparedKey]) -> Vec<PathBuf> {
    let mut failed = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();

    for key in written {
        match std::fs::remove_file(&key.path) {
            Ok(()) => {
                if let Some(dir) = key.path.parent()
                    && !dirs.contains(&dir.to_path_buf())
                {
                    dirs.push(dir.to_path_buf());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => failed.push(key.path.clone()),
        }
    }

    for dir in dirs {
        let _ = std::fs::File::open(&dir).and_then(|d| d.sync_all());
    }
    failed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse::Plan;
    use crate::import::plan::ExistingRouting;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A migrated database in a directory that removes itself.
    struct Db {
        dir: PathBuf,
        conn: Connection,
    }

    impl Db {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "pigeon-recheck-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("pigeon.db");
            let mut conn = pigeon_db::open(&path).unwrap();
            pigeon_db::migrate(&mut conn, &path).unwrap();
            Self { dir, conn }
        }
    }

    impl Drop for Db {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn prepared_with(scoped: Vec<ExistingRouting>, new_domains: Vec<String>) -> Prepared {
        Prepared {
            plan: Plan::default(),
            mode: Mode::Replace,
            new_domains,
            existing_domains: scoped.iter().map(|s| s.domain.clone()).collect(),
            unchanged: 0,
            scoped,
        }
    }

    /// These test the *guard*, not the race.
    ///
    /// The window it defends is real — key generation takes about a minute for
    /// forty domains, and `--replace` was confirmed before it started — but
    /// reproducing the race in a single-process test would mean timing, and a
    /// timing-dependent test of a safety property is worse than none. So the
    /// guard is driven directly with a plan that no longer matches, which is
    /// exactly the state the race produces.
    #[test]
    fn a_domain_that_gained_an_alias_aborts_the_import() {
        let db = Db::new("gained");
        repo::add_domain(&db.conn, "example.com", None).unwrap();

        // Planned when the domain was empty. Captured rather than hand-built:
        // the fingerprint is the whole point, and a literal would let the test
        // assert against a shape the real capture does not produce.
        let prepared = prepared_with(
            vec![existing_routing(&db.conn, "example.com").unwrap()],
            vec![],
        );

        // Somebody adds one while the keys are being generated. Under
        // `--replace` the import would delete it without it ever having been in
        // front of the confirmation.
        repo::add_alias(
            &db.conn,
            "example.com",
            "added-since",
            AliasKind::Forward,
            &[repo::Address::parse("me@example.net").unwrap()],
        )
        .unwrap();

        match recheck_plan(&db.conn, &prepared) {
            Err(ApplyError::Conflicts(c)) => {
                assert_eq!(c[0].kind, ConflictKind::StateChanged);
                assert!(c[0].message.contains("example.com"), "{}", c[0].message);
            }
            other => panic!("an import proceeded against a plan that had moved: {other:?}"),
        }
    }

    #[test]
    fn replacing_one_alias_with_another_aborts_the_import() {
        // The case a count cannot see, and the reason the capture is a
        // fingerprint.
        //
        //   planned:    2 aliases
        //   meanwhile:  A removed, B added
        //   a count:    still 2 -> unchanged
        //
        // `--replace` would then delete B, which was never in front of the
        // confirmation.
        let db = Db::new("substitution");
        let to = repo::Address::parse("me@example.net").unwrap();
        repo::add_domain(&db.conn, "example.com", Some(&to)).unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&to),
        )
        .unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "b",
            AliasKind::Forward,
            std::slice::from_ref(&to),
        )
        .unwrap();

        let planned = existing_routing(&db.conn, "example.com").unwrap();
        assert_eq!(planned.aliases, 2);
        let prepared = prepared_with(vec![planned], vec![]);

        // Same count, different content.
        repo::remove_alias(&db.conn, "example.com", "a").unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "c",
            AliasKind::Forward,
            std::slice::from_ref(&to),
        )
        .unwrap();

        match recheck_plan(&db.conn, &prepared) {
            Err(ApplyError::Conflicts(c)) => {
                assert_eq!(c[0].kind, ConflictKind::StateChanged);
                assert!(c[0].message.contains("alias a"), "{}", c[0].message);
                assert!(c[0].message.contains("alias c"), "{}", c[0].message);
            }
            other => panic!("a same-count substitution passed the re-check: {other:?}"),
        }
    }

    #[test]
    fn changing_an_alias_destination_aborts_the_import() {
        // Same count, same patterns, different target.
        let db = Db::new("retargeted");
        let one = repo::Address::parse("one@example.net").unwrap();
        let two = repo::Address::parse("two@example.net").unwrap();
        repo::add_domain(&db.conn, "example.com", Some(&one)).unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&one),
        )
        .unwrap();

        let prepared = prepared_with(
            vec![existing_routing(&db.conn, "example.com").unwrap()],
            vec![],
        );

        repo::remove_alias(&db.conn, "example.com", "a").unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "a",
            AliasKind::Forward,
            std::slice::from_ref(&two),
        )
        .unwrap();

        assert!(
            matches!(
                recheck_plan(&db.conn, &prepared),
                Err(ApplyError::Conflicts(_))
            ),
            "a retargeted alias passed the re-check"
        );
    }

    #[test]
    fn changing_the_domain_default_under_an_inheriting_alias_aborts_the_import() {
        // The alias row does not move, and what it does changes. The capture
        // records the *effective* destination for exactly this.
        let db = Db::new("inheriting");
        let one = repo::Address::parse("one@example.net").unwrap();
        let two = repo::Address::parse("two@example.net").unwrap();
        repo::add_domain(&db.conn, "example.com", Some(&one)).unwrap();
        repo::add_alias(&db.conn, "example.com", "a", AliasKind::Forward, &[]).unwrap();

        let prepared = prepared_with(
            vec![existing_routing(&db.conn, "example.com").unwrap()],
            vec![],
        );

        repo::set_default_destination(&db.conn, "example.com", Some(&two)).unwrap();

        assert!(
            matches!(
                recheck_plan(&db.conn, &prepared),
                Err(ApplyError::Conflicts(_))
            ),
            "an inheriting alias whose default moved passed the re-check"
        );
    }

    #[test]
    fn a_domain_that_gained_a_catch_all_aborts_the_import() {
        // The catch-all half of the same window, and the one an alias count
        // would miss.
        let db = Db::new("catchall");
        let to = repo::Address::parse("me@example.net").unwrap();
        repo::add_domain(&db.conn, "example.com", Some(&to)).unwrap();

        let prepared = prepared_with(
            vec![existing_routing(&db.conn, "example.com").unwrap()],
            vec![],
        );

        repo::set_catchall(&db.conn, "example.com", Some(&to)).unwrap();

        assert!(
            matches!(
                recheck_plan(&db.conn, &prepared),
                Err(ApplyError::Conflicts(_))
            ),
            "a catch-all added mid-import was not noticed"
        );
    }

    #[test]
    fn a_domain_created_since_the_plan_aborts_the_import() {
        // Its key is already written and `add_domain` would refuse anyway; the
        // point is that the message says why rather than reporting a duplicate.
        let db = Db::new("created");
        let prepared = prepared_with(vec![], vec!["example.com".into()]);

        repo::add_domain(&db.conn, "example.com", None).unwrap();

        match recheck_plan(&db.conn, &prepared) {
            Err(ApplyError::Conflicts(c)) => {
                assert_eq!(c[0].kind, ConflictKind::StateChanged);
                assert!(
                    c[0].message.contains("was created while"),
                    "{}",
                    c[0].message
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unchanged_plan_passes() {
        let db = Db::new("unchanged");
        let to = repo::Address::parse("me@example.net").unwrap();
        repo::add_domain(&db.conn, "example.com", Some(&to)).unwrap();
        repo::add_alias(
            &db.conn,
            "example.com",
            "hello",
            AliasKind::Forward,
            std::slice::from_ref(&to),
        )
        .unwrap();

        let prepared = prepared_with(
            vec![existing_routing(&db.conn, "example.com").unwrap()],
            vec![],
        );

        recheck_plan(&db.conn, &prepared).expect("an unchanged plan was refused");
    }
}
