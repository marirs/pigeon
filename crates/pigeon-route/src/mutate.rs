//! The mutation contract.
//!
//! Every change to the control plane goes through [`mutate`], in this order and
//! no other:
//!
//! ```text
//! 1. apply the mutation
//! 2. build and validate the prospective snapshot, inside the transaction
//! 3. roll back on failure
//! 4. commit
//! 5. publish the snapshot
//! ```
//!
//! # Why the order is the contract
//!
//! **Step 2 inside the transaction is what makes "prospective" mean anything.**
//! The snapshot is built from exactly the state that is about to become real.
//! Building it before the write would validate a state the write might not
//! produce; building it after the commit would mean the invalid configuration
//! was already live when it was found.
//!
//! **Step 5 after the commit** is the only ordering in which the published
//! table and the stored rows cannot disagree. Publishing first would leave a
//! window where the router serves a configuration that a failed commit means
//! nobody asked for.
//!
//! Between commit and publish, lookups use the previous snapshot — a bounded
//! window in which Pigeon is behind its own database, which is the same window
//! a reload has. The routing table is allowed to be stale. It is never allowed
//! to be invalid.
//!
//! # Why this is a function and not a convention
//!
//! `Router::publish` takes a `Snapshot`, and the only way to obtain one is
//! `Snapshot::build`, which validates. So an unvalidated table cannot be
//! published — not because callers are careful, but because there is no such
//! value to hand it.

use rusqlite::{Connection, TransactionBehavior};

use crate::snapshot::{BuildError, Report, Snapshot};
use crate::{LoadError, Router};

#[derive(Debug, thiserror::Error)]
pub enum MutationError {
    #[error("{0}")]
    Db(#[from] pigeon_db::DbError),

    #[error("{0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("cannot read the routing configuration back: {0}")]
    Load(#[from] LoadError),

    #[error(
        "this change would leave the routing configuration in a state Pigeon cannot serve, \
         so nothing was changed:\n\n  {0}"
    )]
    Invalid(#[from] BuildError),
}

/// What a successful mutation produced.
#[derive(Debug)]
pub struct Outcome<T> {
    /// Whatever the mutation itself returned.
    pub value: T,
    /// Non-fatal findings about the configuration that is now live.
    pub reports: Vec<Report>,
}

/// Apply a change under the contract above.
///
/// `apply` runs inside the transaction and must not commit. Anything it returns
/// comes back in [`Outcome::value`]; anything it errors with rolls the whole
/// change back, including any rows it had already written.
///
/// The snapshot is published only if every step succeeded.
pub fn mutate<T, E>(
    conn: &mut Connection,
    router: &Router,
    apply: impl FnOnce(&Connection) -> Result<T, E>,
) -> Result<Outcome<T>, MutationError>
where
    MutationError: From<E>,
{
    // `Immediate` takes the write lock now rather than on first write. The
    // alternative is discovering the lock is held after the mutation has been
    // composed, which for a preview-then-confirm command means the preview was
    // computed against a state that has since moved.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // 1.
    let value = apply(&tx)?;

    // 2. Read back through the transaction, so what is validated is the state
    // the mutation just produced and not the state on disk.
    let built = Snapshot::build(crate::load(&tx)?)?;

    // 3. Any `?` above returns without committing, and `Transaction` rolls back
    // when it is dropped. The rollback is the default rather than a step
    // somebody has to remember, which is the point.

    // 4.
    tx.commit()?;

    // 5. After the commit. Never before.
    router.publish(built.snapshot);

    Ok(Outcome {
        value,
        reports: built.reports,
    })
}

/// Build the snapshot a mutation *would* produce, without keeping it.
///
/// For `--dry-run`: the change is applied, validated and then rolled back, so
/// the preview is of the real outcome rather than of a model of it. Nothing is
/// committed and nothing is published.
pub fn preview<T, E>(
    conn: &mut Connection,
    apply: impl FnOnce(&Connection) -> Result<T, E>,
) -> Result<Outcome<T>, MutationError>
where
    MutationError: From<E>,
{
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let value = apply(&tx)?;
    let built = Snapshot::build(crate::load(&tx)?)?;
    // Explicit, though dropping would do the same: a reader should not have to
    // know that to see that nothing is kept.
    tx.rollback()?;

    Ok(Outcome {
        value,
        reports: built.reports,
    })
}
