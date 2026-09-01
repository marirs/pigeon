//! The routing revision, and the rules for acting on it.
//!
//! `M1-RELOAD.md` C-1 to C-3 are constraints on this file, restated here
//! because a constraint behind a cross-reference is one that gets lost.
//!
//! - **C-1: publication needs one order.** Two things can install a runtime —
//!   the poll and, later, a daemon-owned commit — and nothing about the swap
//!   orders them. The answer chosen (R-6) is a coordinator: one critical
//!   section spanning observation, load, validation and publication, so
//!   ordering comes from the lock rather than from any number. A candidate
//!   built outside it cannot exist, which is what makes "a stale candidate may
//!   only lose publication" true by construction.
//!
//! - **C-2: a revision is only meaningful within one database.** A restore can
//!   present the same number over different rows, so the counter alone cannot
//!   be trusted. Periodic reconciliation — load and fingerprint, regardless of
//!   the number — is what makes it safe in between.
//!
//! - **C-3: those two do not compose naively.** The baseline is a *high-water
//!   mark* within a lineage, and both a regression and an equal revision over
//!   different rows advance the lineage. Only the coordinator advances either.

use rusqlite::Connection;

/// Read the counter.
///
/// A missing row means a database that predates the counter or one that has
/// been damaged; either way the caller cannot reason about revisions, and
/// treating it as zero would look like a regression from every real value.
pub fn read(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT revision FROM routing_revision WHERE id = 1",
        [],
        |r| r.get(0),
    )
    .optional()
}

/// What the coordinator decided about an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// Nothing new since the highest revision this lineage has seen.
    Unchanged,
    /// A forward change: rebuild and publish.
    Advanced,
    /// The counter went *backwards*, which one database's own writes cannot
    /// produce. A restore, and the lineage resets immediately: everything
    /// published under the old one must lose to what follows.
    Regressed,
    /// The counter cannot be read. Nothing is published on a guess.
    Unknown,
}

/// The coordinator's state: which lineage, and how far it has seen.
///
/// Not public. It exists only inside the lock, and handing it out would be
/// handing out the ability to decide publication order somewhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Baseline {
    /// Advanced by a regression, and by reconciliation finding different rows
    /// at the same revision. Daemon-local, and compared before the revision.
    pub lineage: u64,
    /// The **high-water** revision seen in this lineage — not the one it was
    /// established at.
    ///
    /// High-water because a second restore to a revision this lineage has
    /// already passed would otherwise compare equal and be missed: establish
    /// at 5, take a change at 6, restore to 5 again, and an establishment
    /// baseline sees "the same rewound database" while the daemon serves
    /// revision 6's routing over revision 5's rows.
    pub revision: i64,
    /// The fingerprint of the routing last **successfully** published in this
    /// lineage, or `None` before anything has been.
    ///
    /// Beside the revision because it answers the question the revision cannot:
    /// a restore can present the same number over different rows, and only the
    /// rows themselves separate "nothing happened" from "everything changed
    /// underneath us" (C-2). Kept here rather than read back from the served
    /// runtime so that the value reconciliation compares is the one this lock
    /// owns and writes.
    published: Option<[u8; 32]>,
}

impl Baseline {
    pub fn new(revision: i64) -> Self {
        Self {
            lineage: 0,
            revision,
            published: None,
        }
    }

    /// Record a successful publication.
    pub fn published(&mut self, fingerprint: [u8; 32]) {
        self.published = Some(fingerprint);
    }

    /// What was last published, if anything.
    ///
    /// `None` compares equal to nothing, so a coordinator that has never
    /// published reconciles into publishing rather than concluding that
    /// whatever is loaded is already live.
    pub fn published_fingerprint(&self) -> Option<[u8; 32]> {
        self.published
    }

    /// Classify an observation and update the baseline.
    ///
    /// Both outer cases move the baseline, and both move it *before* the
    /// rebuild is attempted: a failed rebuild at 7 still leaves the baseline at
    /// 7, so a later 6 is correctly a rewind rather than a fresh forward
    /// change.
    pub fn observe(&mut self, observed: Option<i64>) -> Observation {
        let Some(observed) = observed else {
            return Observation::Unknown;
        };

        if observed < self.revision {
            // A regression is detectable without loading anything, but handling
            // it is not: the rows at the lower revision may differ from what is
            // published, so the lineage advances *and* a rebuild follows.
            self.lineage += 1;
            self.revision = observed;
            Observation::Regressed
        } else if observed > self.revision {
            self.revision = observed;
            Observation::Advanced
        } else {
            Observation::Unchanged
        }
    }

    /// Advance the lineage because reconciliation found different rows at the
    /// same revision — the restore C-2 describes, which no comparison of
    /// numbers can see.
    pub fn diverged(&mut self) {
        self.lineage += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forward_change_advances_the_baseline() {
        let mut b = Baseline::new(5);
        assert_eq!(b.observe(Some(6)), Observation::Advanced);
        assert_eq!(b.revision, 6);
        assert_eq!(b.lineage, 0);
    }

    #[test]
    fn an_unchanged_revision_is_not_a_rebuild() {
        let mut b = Baseline::new(5);
        assert_eq!(b.observe(Some(5)), Observation::Unchanged);
    }

    #[test]
    fn a_regression_resets_the_lineage_immediately() {
        // A restore. The rows at the lower revision may differ from what is
        // published, so this is not merely "nothing new".
        let mut b = Baseline::new(10);
        assert_eq!(b.observe(Some(5)), Observation::Regressed);
        assert_eq!(b.lineage, 1);
        assert_eq!(b.revision, 5);
    }

    #[test]
    fn the_baseline_is_a_high_water_mark() {
        // Establish at 5, move to 6, restore to 5 again. Against an
        // establishment baseline the second restore compares equal and is
        // missed, and the daemon serves revision 6's routing over a database
        // holding revision 5's rows.
        let mut b = Baseline::new(5);
        assert_eq!(b.observe(Some(6)), Observation::Advanced);
        assert_eq!(b.observe(Some(5)), Observation::Regressed);
        assert_eq!(b.lineage, 1);
    }

    #[test]
    fn the_baseline_moves_even_when_the_rebuild_that_follows_would_fail() {
        // `observe` records what was seen; whether the rebuild succeeds is the
        // caller's problem. If a failed rebuild left the baseline behind, a
        // later lower revision would read as a forward change.
        let mut b = Baseline::new(5);
        b.observe(Some(7));
        assert_eq!(b.revision, 7);
        assert_eq!(b.observe(Some(6)), Observation::Regressed);
    }

    #[test]
    fn an_unreadable_counter_publishes_nothing() {
        // Treating a missing counter as zero would look like a regression from
        // every real value, and reset the lineage on every poll.
        let mut b = Baseline::new(5);
        assert_eq!(b.observe(None), Observation::Unknown);
        assert_eq!(b.revision, 5, "an unknown observation moved the baseline");
        assert_eq!(b.lineage, 0);
    }

    #[test]
    fn divergence_advances_the_lineage_without_touching_the_revision() {
        // Reconciliation found different rows at the same number. The lineage
        // is what makes the rebuilt table win; the revision has not moved.
        let mut b = Baseline::new(5);
        b.diverged();
        assert_eq!(b.lineage, 1);
        assert_eq!(b.revision, 5);
    }
}
