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

use std::io;
use std::path::{Path, PathBuf};

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
#[derive(Debug, Clone)]
pub struct Spool {
    root: PathBuf,
}

impl Spool {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
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

/// Flush a directory, so a name created or removed inside it is durable.
async fn sync_dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::File::open(&dir)?.sync_all())
        .await
        .map_err(io::Error::other)?
}
