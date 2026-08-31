//! `pigeon srs keys` and `pigeon srs rotate`, through the real binary.
//!
//! The ring is the one piece of state whose loss is invisible until somebody's
//! mail bounces and the bounce cannot be routed home — so these tests are about
//! what survives: every existing key, the file's permissions, and the ring
//! itself when a rotation fails partway.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

const FIRST_KEY: &str = "1 2026-01-01T00:00:00Z - AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n";

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-srs-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        std::fs::create_dir_all(dir.join("spool")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for sub in ["keys", "secrets"] {
                std::fs::set_permissions(dir.join(sub), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
        }

        let f = Self { dir };
        f.write_ring(FIRST_KEY);
        std::fs::write(
            f.dir.join("pigeon.toml"),
            format!(
                "hostname = \"pigeon.test\"\n\
                 database = \"{d}/pigeon.db\"\n\
                 spool = \"{d}/spool\"\n\
                 keys = \"{d}/keys\"\n\
                 secrets = \"{d}/secrets\"\n\
                 srs_secret_file = \"{d}/srs.key\"\n",
                d = f.dir.display()
            ),
        )
        .unwrap();
        f
    }

    fn ring_path(&self) -> PathBuf {
        self.dir.join("srs.key")
    }

    fn write_ring(&self, content: &str) {
        std::fs::write(self.ring_path(), content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(self.ring_path(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }

    fn ring(&self) -> String {
        std::fs::read_to_string(self.ring_path()).unwrap()
    }

    fn run(&self, args: &[&str]) -> (String, String, bool) {
        let out = Command::new(env!("CARGO_BIN_EXE_pigeon"))
            .arg("--config")
            .arg(self.dir.join("pigeon.toml"))
            .args(args)
            .output()
            .expect("run pigeon");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.success(),
        )
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut with_json: Vec<&str> = args.to_vec();
        with_json.push("--json");
        let (stdout, _, ok) = self.run(&with_json);
        assert!(ok, "{args:?} failed: {stdout}");
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

// ------------------------------------------------------------------- keys

#[test]
fn keys_reports_which_one_signs() {
    let f = Fixture::new("keys");
    let out = f.json(&["srs", "keys"]);

    assert_eq!(out["format_version"], 1);
    assert_eq!(out["error"], Value::Null);
    let keys = out["keys"].as_array().expect("keys is an array");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], 1);
    assert_eq!(keys[0]["signing"], true);
    // A key that still signs has no deletion date, and says so with null
    // rather than by omitting the field — an absent field and a null one mean
    // different things to a consumer, and only one of them is checkable.
    assert_eq!(keys[0]["may_be_deleted_after"], Value::Null);
}

// ----------------------------------------------------------------- rotate

#[test]
fn rotation_adds_a_key_and_keeps_every_existing_one() {
    let f = Fixture::new("rotate");
    let before = f.ring();

    let out = f.json(&["srs", "rotate"]);
    assert_eq!(out["signing_key_id"], 2);
    assert_eq!(out["keys"], 2);
    assert_eq!(out["retention_days"], 30);
    assert!(out["displaced_key_deletable_after"].is_string());

    let after = f.ring();
    // The whole of the previous key, secret included: rewriting the ring must
    // carry it across untouched or every address it signed stops verifying.
    let secret = before.split_whitespace().next_back().unwrap();
    assert!(
        after.contains(secret),
        "the previous secret was lost:\n{after}"
    );

    // The new key signs, which is position rather than id — the first entry is
    // the signing key and the loader refuses a ring whose first entry has
    // stopped signing.
    let listed = f.json(&["srs", "keys"]);
    let keys = listed["keys"].as_array().unwrap();
    assert_eq!(keys[0]["id"], 2);
    assert_eq!(keys[0]["signing"], true);
    assert_eq!(keys[1]["id"], 1);
    assert_eq!(keys[1]["signing"], false);
    assert!(keys[1]["may_be_deleted_after"].is_string());
    assert_eq!(keys[1]["deletable_now"], false);
}

#[test]
fn rotation_never_deletes() {
    // Two rotations, and the first key is still there. Deleting it is an
    // operator's decision because only an operator knows whether mail signed
    // under it has finished arriving.
    let f = Fixture::new("no-delete");
    f.json(&["srs", "rotate"]);
    f.json(&["srs", "rotate"]);

    let keys = f.json(&["srs", "keys"]);
    let ids: Vec<u64> = keys["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![3, 2, 1]);
}

#[test]
fn the_new_ring_is_still_private() {
    // A ring readable for an instant is a ring that was readable. The
    // replacement is written 0600 from the moment it exists, not chmodded
    // afterwards.
    let f = Fixture::new("mode");
    f.json(&["srs", "rotate"]);
    #[cfg(unix)]
    assert_eq!(mode(&f.ring_path()), 0o600, "the rotated ring is not 0600");
}

#[test]
fn rotation_is_refused_at_the_cap() {
    // Refused rather than silently dropping the oldest key — which is the one
    // whose addresses are closest to expiring, and therefore the one most
    // likely to be needed by a bounce still in flight.
    let f = Fixture::new("cap");
    let mut ring = String::new();
    for id in (1..=8).rev() {
        ring.push_str(&format!(
            "{id}  2026-01-0{id}T00:00:00Z  {}  AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
            if id == 8 {
                "-".to_string()
            } else {
                "2026-02-01T00:00:00Z".to_string()
            }
        ));
    }
    f.write_ring(&ring);
    let before = f.ring();

    let (stdout, stderr, ok) = f.run(&["srs", "rotate"]);
    assert!(!ok, "a ninth key was accepted: {stdout}");
    assert!(
        stderr.contains("maximum") || stdout.contains("maximum"),
        "the refusal does not say why: {stderr}{stdout}"
    );
    assert_eq!(
        f.ring(),
        before,
        "the ring was modified by a refused rotation"
    );
}

#[test]
fn a_rotation_in_progress_blocks_another() {
    // Two rotations racing would each read the ring, add a key and write, and
    // the second would drop the first's key along with every address it had
    // already signed.
    let f = Fixture::new("lock");
    let mut lock = f.ring_path().into_os_string();
    lock.push(".lock");
    std::fs::write(&lock, "").unwrap();

    let before = f.ring();
    let (stdout, stderr, ok) = f.run(&["srs", "rotate"]);
    assert!(!ok, "a rotation ran while another held the lock: {stdout}");
    assert!(
        stderr.contains("in progress") || stdout.contains("in progress"),
        "the refusal does not say why: {stderr}{stdout}"
    );
    assert_eq!(f.ring(), before, "the ring was modified while locked");

    // And the lock is not a permanent state: clearing it lets a rotation run.
    std::fs::remove_file(&lock).unwrap();
    f.json(&["srs", "rotate"]);
    assert_ne!(f.ring(), before);
}

#[test]
fn a_failed_rotation_leaves_no_temporary_ring_behind() {
    // Key material in a file nothing references and nothing will clean up is
    // the failure mode `write_private_key` was already fixed for once.
    let f = Fixture::new("tmp");
    f.json(&["srs", "rotate"]);

    let leftovers: Vec<String> = std::fs::read_dir(&f.dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".rotate.") || n.ends_with(".lock"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

#[test]
fn an_unreadable_ring_is_refused_rather_than_replaced() {
    // Rotation reads before it writes. A ring that will not parse is an
    // operator error, and overwriting it would destroy whatever keys it still
    // held in the course of "fixing" it.
    let f = Fixture::new("garbage");
    f.write_ring("this is not a key ring\n");
    let before = f.ring();

    let (_, _, ok) = f.run(&["srs", "rotate"]);
    assert!(!ok, "a rotation ran against an unreadable ring");
    assert_eq!(f.ring(), before);
}
