//! SQLite storage: schema, migrations, repositories.
//!
//! Holds routing configuration and queue metadata. Message bodies never enter
//! the database; they live in the spool.
//!
//! Rules that are not negotiable:
//! - parameterised queries only, never string-built SQL
//! - foreign keys on
//! - migrations run inside a transaction
//! - WAL mode
//!
//! The schema and the reasoning behind each constraint are in
//! `docs/M1-SCHEMA.md`.
//!
//! # Repositories are not here yet, deliberately
//!
//! Mutating operations wait for the validated snapshot builder. `M1-SCHEMA.md`
//! S-2 makes snapshot construction the enforcement point for every invariant
//! SQLite cannot express — a reject alias with destinations, a routing loop —
//! and a write that cannot be validated against a proposed snapshot has nothing
//! validating it. Adding writes first would mean building the thing that
//! creates invalid rows before the thing that refuses them.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rusqlite::Connection;

pub mod migrate;

pub use migrate::{Applied, MIGRATIONS, Migration, migrate};

/// Everything that can go wrong opening or migrating the database.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("cannot open database at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error(
        "database is at schema version {database}, but this build only knows {binary}. \
         It was written by a newer Pigeon; upgrade rather than downgrade."
    )]
    DatabaseFromTheFuture { database: u32, binary: u32 },

    #[error(
        "migration {version} ({name}) has changed since it was applied \
         (recorded {recorded}, now {actual}). Migrations are immutable once released; \
         make the correction in a new migration."
    )]
    ChecksumMismatch {
        version: u32,
        name: &'static str,
        recorded: String,
        actual: String,
    },

    #[error("migration history has a gap: expected version {expected}, found {found}")]
    VersionGap { expected: u32, found: u32 },

    #[error("migration {version} was applied by another build and is unknown here")]
    UnknownMigration { version: u32 },

    #[error("migration {version} ({name}) failed: {source}")]
    MigrationFailed {
        version: u32,
        name: &'static str,
        #[source]
        source: rusqlite::Error,
    },

    #[error("migration {version} is not valid UTF-8")]
    MigrationNotUtf8 { version: u32 },

    #[error("foreign key violations after migrating: {}", .0.join(", "))]
    ForeignKeyViolations(Vec<String>),

    #[error("could not write the pre-migration backup to {path}: {source}")]
    BackupFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Pragma(String),
}

/// How long to wait for another writer before giving up.
///
/// The CLI and the daemon can both want the database. Failing instantly on a
/// lock held for milliseconds would make ordinary concurrent use look like an
/// error.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Open the database for writing, with the pragmas every connection needs.
///
/// Does not migrate. Callers that should migrate say so — only the daemon does
/// (`M1-SCHEMA.md` I7).
pub fn open(path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(path).map_err(|source| DbError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    configure(&conn, false)?;
    Ok(conn)
}

/// Open the database read-only, for CLI read commands.
///
/// Read-only rather than merely by convention: `ARCHITECTURE.md` §3.3 has
/// mutations go through the daemon so there is one writer, and a connection
/// that *cannot* write enforces that rather than trusting every command not to.
pub fn open_read_only(path: &Path) -> Result<Connection, DbError> {
    use rusqlite::OpenFlags;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|source| DbError::Open {
        path: path.to_path_buf(),
        source,
    })?;
    configure(&conn, true)?;
    Ok(conn)
}

/// Set the pragmas that are not stored in the file.
fn configure(conn: &Connection, read_only: bool) -> Result<(), DbError> {
    conn.busy_timeout(BUSY_TIMEOUT)?;

    if !read_only {
        // Persistent once set, but setting it costs nothing and a database
        // created by something else may not have it.
        let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(DbError::Pragma(format!(
                "could not enable WAL journal mode (got {mode:?}); \
                 the database may be on a filesystem that does not support it"
            )));
        }
    }

    // Per connection, not persistent. This is the single most common way a
    // SQLite schema's referential integrity turns out to be decorative, so it
    // is set here — in the one place connections are made — and asserted.
    conn.pragma_update(None, "foreign_keys", true)?;
    let on: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?;
    if on != 1 {
        return Err(DbError::Pragma(
            "foreign keys did not stay enabled on this connection".to_string(),
        ));
    }

    Ok(())
}

/// The schema version recorded in the file.
pub fn schema_version(conn: &Connection) -> Result<u32, DbError> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}
