//! The `pigeon` command line interface.
//!
//! # Shape
//!
//! Every command reads `pigeon <noun> <verb> [target] [arguments]`.
//!
//! Nouns are few and stable. Verbs repeat across nouns — `list`, `add`,
//! `remove`, `show`, `check`, `test` — so learning one noun teaches the rest.
//! Where a verb would only make sense for one noun, that is a sign the noun is
//! wrong.
//!
//! Singular acts on one thing, plural on all of them:
//!
//! ```text
//! pigeon domain check example.com   # one
//! pigeon domains check              # all
//! ```
//!
//! Forwarding rules — aliases, catch-all, reject — all live under `alias`,
//! because they are one concept with a precedence order rather than three
//! unrelated features.
//!
//! # Help is part of the interface
//!
//! Three rules, applied without exception:
//!
//! 1. **A bare noun prints its own help and exits zero.** `pigeon domain` is
//!    someone asking what they can do to a domain, not a usage error.
//! 2. **Every help page ends with worked examples.** A syntax summary alone
//!    leaves the reader guessing at argument order, which is the actual
//!    question they had.
//! 3. **Every error names the fix.** Not just what was wrong — the command that
//!    puts it right, or the near-miss that was probably intended.
//!
//! Commands with an obvious next step print it. Adding a domain says to check
//! it; a failing check prints the record to publish. The operator should never
//! have to consult documentation to find out what to do next.
//!
//! # Where commands run
//!
//! Read commands open SQLite directly. Mutating commands go through the
//! daemon's Unix socket while it is running, so there is only ever one writer
//! and changes are validated against live state before they commit. Offline
//! mutation is permitted only when the daemon is stopped.
//!
//! # The `--json` contract
//!
//! Every read command supports `--json`, and that output is stable across
//! releases. It is the seam anything built on top of Pigeon consumes, and a
//! process boundary keeps such integrations free of any coupling to the
//! database schema.
//!
//! `--quiet` prints nothing on success and relies on the exit code, which is
//! also stable — see `docs/CLI.md`.

/// Mutating commands are blocked, deliberately and by design rather than by
/// omission.
///
/// `M1-SCHEMA.md` S-2 makes routing-snapshot construction the enforcement point
/// for every invariant SQLite cannot express: a reject alias carrying
/// destinations, a catch-all with no reachable destination, an alias that
/// forwards into a loop. The snapshot builder is not written.
///
/// So a write today would have nothing validating it. Shipping `domain add`
/// first would mean building the thing that creates invalid rows before the
/// thing that refuses them, and every row it created in the meantime would need
/// re-validating by whatever came later.
///
/// The database and the migration runner are real: `pigeond` will create and
/// migrate a database, validate its configuration and refuse to start on
/// anything local that is wrong.
fn main() -> std::process::ExitCode {
    eprintln!(
        "pigeon: not yet implemented.

The control plane exists as far as storage: `pigeond` creates and migrates its
database, validates configuration, and refuses to start on local
misconfiguration.

What is missing is the routing snapshot, which is where every rule the database
cannot express is enforced — reject aliases, catch-all reachability, forwarding
loops. Until it exists there are no commands that write, because a write with
nothing validating it is the problem rather than progress.

  Roadmap:  docs/ROADMAP.md
  Schema:   docs/M1-SCHEMA.md"
    );
    // 1: command or configuration error (CLI.md, exit codes).
    std::process::ExitCode::from(1)
}
