//! Putting a message on disk so that a `250` can be promised.
//!
//! Acceptance orders three things, and the order is the promise
//! (`M3-DESIGN.md` §4):
//!
//! 1. the contents **and the directory entry** are durable,
//! 2. the queue rows commit atomically,
//! 3. only then is the sender told `250`.
//!
//! Anything that fails before step 2 must remove what step 1 wrote — and
//! nothing after step 2 may remove it, because from that instant the message is
//! owed to somebody.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// Something already occupies this identifier.
    ///
    /// Its own variant rather than an `io::Error`, because it means a
    /// generator collided and that is a bug, not a disk problem — and the
    /// existing file belongs to a message somebody was already promised.
    #[error("spool identifier collision: {0} already exists")]
    Collision(PathBuf),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
}

impl SpoolError {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

/// A generated spool name.
///
/// A type rather than a `&str` because the one rule about these names is that
/// they are *generated* — never sender or recipient text — and a rule enforced
/// at every call site is a rule enforced at all but one of them. Everything
/// that could turn a name into a path is refused here, once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpoolId(String);

impl SpoolId {
    pub fn new(id: &str) -> Result<Self, InvalidSpoolId> {
        if id.is_empty() {
            return Err(InvalidSpoolId::Empty);
        }
        // Deliberately narrow: identifiers are generated, so the alphabet is
        // ours to choose, and anything outside it is a sign the caller passed
        // something it should not have.
        if !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(InvalidSpoolId::Charset(id.to_string()));
        }
        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SpoolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvalidSpoolId {
    #[error("a spool identifier cannot be empty")]
    Empty,
    #[error(
        "a spool identifier may hold only letters, digits, `-` and `_`; got {0:?}. \
         These names are generated, so anything else means an address or a path \
         reached a place that only ever holds an identifier."
    )]
    Charset(String),
}

/// The spool directory.
///
/// Also the register of installs in progress. A file is deliberately
/// unreferenced between being installed and its transaction committing, so a
/// sweep that collected unreferenced files would delete exactly the message
/// that is one instant away from being acknowledged.
///
/// An age heuristic would only make that window narrower, not closed: "old
/// enough that no acceptance could still be running" is a guess about
/// scheduling, and it is wrong on a machine that is paused, swapping, or
/// stopped in a debugger. The register is exact — and it lives in memory
/// deliberately, because after a crash there is no acceptance in progress and
/// every one of those files really is collectable.
#[derive(Debug, Clone)]
pub struct Spool {
    root: PathBuf,
    active: Arc<Mutex<HashSet<String>>>,
}

/// An install that has not been committed yet.
///
/// Holds the identifier in the register until it is dropped, which the caller
/// does after its transaction commits — or after it rolls back and removes the
/// file.
#[derive(Debug)]
pub struct Pending {
    id: SpoolId,
    active: Arc<Mutex<HashSet<String>>>,
}

impl Pending {
    pub fn id(&self) -> &SpoolId {
        &self.id
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(self.id.as_str());
        }
    }
}

impl Spool {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            active: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Register an install that is about to happen, so the sweep leaves it
    /// alone until the returned guard is dropped.
    pub fn begin(&self, id: &SpoolId) -> Pending {
        if let Ok(mut active) = self.active.lock() {
            active.insert(id.as_str().to_string());
        }
        Pending {
            id: id.clone(),
            active: Arc::clone(&self.active),
        }
    }

    /// Remove spool files that nothing refers to and nothing is installing.
    ///
    /// `referenced` is what the database knows about. Anything on disk that is
    /// neither referenced nor mid-install was written by an acceptance that
    /// crashed before its commit: the sender was never told `250`, so the file
    /// is nobody's.
    ///
    /// Returns how many were removed.
    pub async fn sweep(&self, referenced: &HashSet<String>) -> Result<usize, SpoolError> {
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(|e| SpoolError::io(format!("reading {}", self.root.display()), e))?;

        let mut removed = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".eml") else {
                // Partial files are left alone: one may belong to a write that
                // is in progress this instant, and deleting it destroys mail in
                // flight to save a few bytes.
                continue;
            };
            if referenced.contains(stem) {
                continue;
            }
            if self.active.lock().map(|a| a.contains(stem)).unwrap_or(true) {
                // Mid-install, or the register is poisoned. Either way, leaving
                // the file is the safe direction.
                continue;
            }

            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(path = %entry.path().display(), error = %e, "cannot sweep");
                }
            }
        }

        if removed > 0 {
            sync_dir(&self.root)
                .await
                .map_err(|e| SpoolError::io(format!("flushing {}", self.root.display()), e))?;
        }
        Ok(removed)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(&self, id: &SpoolId) -> PathBuf {
        self.root.join(format!("{id}.eml"))
    }

    fn temp_path(&self, id: &SpoolId) -> PathBuf {
        // A leading dot so a partial file is visibly not a message, and the
        // identifier so two concurrent acceptances cannot share a temporary.
        self.root.join(format!(".{id}.partial"))
    }

    /// Write a message and make it durable, contents and name both.
    ///
    /// Returns once a crash could not lose it — which is what makes it safe for
    /// the caller to commit queue rows referring to it.
    pub async fn install(&self, id: &SpoolId, parts: &[&[u8]]) -> Result<(), SpoolError> {
        let tmp = self.temp_path(id);
        let final_path = self.path(id);

        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // 0600, not whatever the umask happens to be. A spooled file is the
        // plaintext body of somebody's mail, and the usual default makes it
        // readable by every local account.
        // `tokio::fs::OpenOptions::mode` is inherent on unix, so no extension
        // trait is needed here — unlike the std one.
        #[cfg(unix)]
        options.mode(0o600);

        let write = async {
            let mut f = options.open(&tmp).await?;
            for part in parts {
                f.write_all(part).await?;
            }
            // The contents, before the name exists: a directory entry pointing
            // at unwritten data is worse than no entry at all.
            f.sync_all().await
        }
        .await;

        if let Err(e) = write {
            self.discard(&tmp).await;
            return Err(SpoolError::io(format!("writing {}", tmp.display()), e));
        }

        // `hard_link` rather than `rename`, because rename replaces its
        // destination unconditionally. A spooled file belongs to a message that
        // was already acknowledged and may still be awaiting a delivery that
        // failed, so replacing it destroys mail the sender believes was
        // accepted. Linking fails with `AlreadyExists` if the destination is
        // taken — atomically, with no window a `try_exists` check would open.
        let link = tokio::fs::hard_link(&tmp, &final_path).await;

        // The temporary goes either way: on success it is a second name for
        // content now reachable under the final one, and on failure it is a
        // partial message nothing will ever read.
        if let Err(e) = tokio::fs::remove_file(&tmp).await {
            tracing::warn!(path = %tmp.display(), error = %e, "could not remove spool temporary");
        }

        match link {
            Ok(()) => {
                // The name, now that it exists. Without this the contents
                // survive a power failure and the directory entry may not,
                // which is the same loss by a longer route — and it is the step
                // the earlier implementation was missing.
                sync_dir(&self.root)
                    .await
                    .map_err(|e| SpoolError::io(format!("flushing {}", self.root.display()), e))?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(SpoolError::Collision(final_path))
            }
            Err(e) => Err(SpoolError::io(
                format!("linking {}", final_path.display()),
                e,
            )),
        }
    }

    /// Remove an installed message.
    ///
    /// For two callers with opposite reasons: acceptance, undoing an install
    /// whose transaction did not commit, and retention, removing a body whose
    /// deliveries are all terminal. **Never** for a message whose rows are
    /// committed and not yet terminal.
    ///
    /// Idempotent. A missing file is the desired state, and both callers can
    /// arrive after a crash that already did the work.
    pub async fn remove(&self, id: &SpoolId) -> Result<(), SpoolError> {
        let path = self.path(id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => sync_dir(&self.root)
                .await
                .map_err(|e| SpoolError::io(format!("flushing {}", self.root.display()), e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SpoolError::io(format!("removing {}", path.display()), e)),
        }
    }

    pub async fn read(&self, id: &SpoolId) -> Result<Vec<u8>, SpoolError> {
        let path = self.path(id);
        tokio::fs::read(&path)
            .await
            .map_err(|e| SpoolError::io(format!("reading {}", path.display()), e))
    }

    /// Best-effort removal of a partial file, on a path that is already failing.
    async fn discard(&self, tmp: &Path) {
        if let Err(e) = tokio::fs::remove_file(tmp).await
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %tmp.display(), error = %e, "could not remove spool temporary");
        }
    }
}

impl From<SpoolError> for io::Error {
    /// Preserves the kind, which is the part a caller acts on.
    ///
    /// Flattening everything to `Other` loses the distinction between "the
    /// directory is not writable" and "the disk is full", and startup gating
    /// reports the difference to an operator who has to fix one of them.
    fn from(e: SpoolError) -> Self {
        match e {
            SpoolError::Collision(path) => io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "spool identifier collision: {} already exists",
                    path.display()
                ),
            ),
            SpoolError::Io { context, source } => {
                io::Error::new(source.kind(), format!("{context}: {source}"))
            }
        }
    }
}

/// Flush a directory, so a name created or removed inside it is durable.
async fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::File::open(&dir)?.sync_all())
        .await
        .map_err(io::Error::other)?
}
