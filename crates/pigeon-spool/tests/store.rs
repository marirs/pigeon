//! What the spool guarantees, and what it refuses.
//!
//! Durability itself cannot be asserted from a test — an `fsync` that returns
//! having done nothing looks identical from here — so what is tested is
//! everything around it: that a name never appears without its contents, that
//! an existing message is never replaced, and that a failed acceptance leaves
//! nothing behind.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pigeon_spool::{InvalidSpoolId, Spool, SpoolError, SpoolId};

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-spool-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn spool(&self) -> Spool {
        Spool::new(&self.0)
    }

    /// Everything in the directory, temporaries included.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn id(s: &str) -> SpoolId {
    SpoolId::new(s).unwrap()
}

#[tokio::test]
async fn an_installed_message_holds_exactly_what_was_written() {
    let dir = Dir::new("install");
    let spool = dir.spool();
    let m = id("msg-1");

    spool
        .install(&m, &[b"Received: by pigeon\r\n", b"\r\nbody\r\n"])
        .await
        .unwrap();

    assert_eq!(
        spool.read(&m).await.unwrap(),
        b"Received: by pigeon\r\n\r\nbody\r\n"
    );
    // The parts are written in sequence rather than concatenated first, so the
    // seam between them is worth asserting.
    assert_eq!(
        dir.entries(),
        vec!["msg-1.eml"],
        "a temporary was left behind"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_spooled_message_is_not_readable_by_other_accounts() {
    use std::os::unix::fs::PermissionsExt;

    // The plaintext body of somebody's mail. The default under a typical umask
    // is 0644, which publishes every message to every local account.
    let dir = Dir::new("mode");
    let spool = dir.spool();
    let m = id("msg-1");
    spool.install(&m, &[b"body"]).await.unwrap();

    let mode = std::fs::metadata(spool.path(&m))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "spooled message is {mode:04o}");
}

#[tokio::test]
async fn an_existing_message_is_never_replaced() {
    // A spooled file belongs to a message that was already acknowledged and may
    // still be awaiting a delivery that failed. `rename` would overwrite it
    // silently, which destroys mail the sender believes was accepted — so the
    // install is a link, which fails atomically instead.
    let dir = Dir::new("collision");
    let spool = dir.spool();
    let m = id("msg-1");

    spool.install(&m, &[b"the original"]).await.unwrap();

    let err = spool.install(&m, &[b"the replacement"]).await.unwrap_err();
    assert!(matches!(err, SpoolError::Collision(_)), "{err:?}");

    assert_eq!(spool.read(&m).await.unwrap(), b"the original");
    assert_eq!(
        dir.entries(),
        vec!["msg-1.eml"],
        "the failed install left a temporary behind"
    );
}

#[tokio::test]
async fn a_removed_message_is_gone_and_removing_it_again_is_fine() {
    // Idempotent because both callers can arrive after a crash that already did
    // the work: acceptance undoing an install whose transaction never
    // committed, and retention removing a body whose deliveries are terminal.
    let dir = Dir::new("remove");
    let spool = dir.spool();
    let m = id("msg-1");

    spool.install(&m, &[b"body"]).await.unwrap();
    spool.remove(&m).await.unwrap();
    assert!(dir.entries().is_empty(), "{:?}", dir.entries());

    spool
        .remove(&m)
        .await
        .expect("removing twice is not an error");
}

#[tokio::test]
async fn the_identifier_after_removal_can_be_used_again() {
    // Nothing keeps a tombstone, so a generator that reuses an identifier after
    // retention is not blocked by the collision rule.
    let dir = Dir::new("reuse");
    let spool = dir.spool();
    let m = id("msg-1");

    spool.install(&m, &[b"first"]).await.unwrap();
    spool.remove(&m).await.unwrap();
    spool.install(&m, &[b"second"]).await.unwrap();
    assert_eq!(spool.read(&m).await.unwrap(), b"second");
}

#[tokio::test]
async fn reading_a_message_that_is_not_there_is_an_error_not_an_empty_message() {
    // A body deleted by retention while a row still refers to it must not read
    // as a zero-byte message, which would be forwarded as an empty one.
    let dir = Dir::new("missing");
    let spool = dir.spool();
    let err = spool.read(&id("nope")).await.unwrap_err();
    assert!(matches!(err, SpoolError::Io { .. }), "{err:?}");
}

// ------------------------------------------------------------- identifiers

#[test]
fn an_identifier_cannot_become_a_path() {
    // These names are generated. Anything else reaching here means an address
    // or a path arrived where only an identifier belongs, and the containment
    // rule in SECURITY.md is enforced by refusing it rather than by sanitising
    // it into something that looks fine.
    for bad in [
        "../escape",
        "sub/dir",
        "back\\slash",
        ".hidden",
        "with space",
        "alice@example.com",
        "",
    ] {
        assert!(
            SpoolId::new(bad).is_err(),
            "{bad:?} was accepted as a spool identifier"
        );
    }

    assert_eq!(SpoolId::new(""), Err(InvalidSpoolId::Empty));
    assert!(SpoolId::new("msg-01_ABC").is_ok());
}

#[tokio::test]
async fn a_partial_write_leaves_nothing_behind() {
    // The pre-commit failure path: whatever fails before the queue rows commit
    // must leave the directory as it was, or the sweep has orphans to collect
    // that nothing ever created a row for.
    //
    // Driven by making the *final* name unusable — a directory in its place —
    // so the write succeeds and the install cannot.
    let dir = Dir::new("partial");
    let spool = dir.spool();
    let m = id("msg-1");
    std::fs::create_dir(spool.path(&m)).unwrap();

    let err = spool.install(&m, &[b"body"]).await.unwrap_err();
    assert!(matches!(err, SpoolError::Collision(_)), "{err:?}");

    assert_eq!(
        dir.entries(),
        vec!["msg-1.eml"],
        "a temporary survived a failed install"
    );
}

// -------------------------------------------------------------- the sweep

#[tokio::test]
async fn a_file_being_installed_is_not_swept() {
    // The window the register exists for: between the install and the commit
    // the file is deliberately unreferenced, and it is one instant away from
    // being a message somebody was told `250` about.
    let dir = Dir::new("sweep-active");
    let spool = dir.spool();
    let m = id("msg-1");

    let pending = spool.begin(&m);
    spool.install(&m, &[b"body"]).await.unwrap();

    let referenced = std::collections::HashSet::new();
    assert_eq!(
        spool.sweep(&referenced).await.unwrap(),
        0,
        "the sweep took a file that was mid-install"
    );
    assert!(spool.path(&m).exists());

    // Once the transaction is done, the guard goes — and if the transaction did
    // not commit, the file is nobody's.
    drop(pending);
    assert_eq!(spool.sweep(&referenced).await.unwrap(), 1);
    assert!(!spool.path(&m).exists());
}

#[tokio::test]
async fn a_referenced_file_is_never_swept() {
    let dir = Dir::new("sweep-referenced");
    let spool = dir.spool();
    let m = id("msg-1");
    spool.install(&m, &[b"body"]).await.unwrap();

    let referenced: std::collections::HashSet<String> = ["msg-1".to_string()].into_iter().collect();
    assert_eq!(spool.sweep(&referenced).await.unwrap(), 0);
    assert!(spool.path(&m).exists(), "a queued message was swept");
}

#[tokio::test]
async fn the_sweep_leaves_partial_files_alone() {
    // One may belong to a write in progress this instant, and deleting it
    // destroys mail in flight to save a few bytes. They are counted elsewhere
    // so an operator whose disk is filling can see them.
    let dir = Dir::new("sweep-partial");
    let spool = dir.spool();
    std::fs::write(dir.0.join(".msg-1.partial"), b"half").unwrap();

    assert_eq!(
        spool
            .sweep(&std::collections::HashSet::new())
            .await
            .unwrap(),
        0
    );
    assert!(dir.0.join(".msg-1.partial").exists());
}

#[tokio::test]
async fn after_a_restart_an_uncommitted_file_is_collectable() {
    // The register is in memory on purpose: a crash empties it, and after a
    // crash there is no acceptance in progress, so every file it was
    // protecting really is nobody's.
    let dir = Dir::new("sweep-restart");
    {
        let spool = dir.spool();
        let m = id("msg-1");
        let _pending = spool.begin(&m);
        spool.install(&m, &[b"body"]).await.unwrap();
        // The process ends here, guard and register with it.
    }

    let after_restart = dir.spool();
    assert_eq!(
        after_restart
            .sweep(&std::collections::HashSet::new())
            .await
            .unwrap(),
        1,
        "a file left by a crashed acceptance was not collected"
    );
}
