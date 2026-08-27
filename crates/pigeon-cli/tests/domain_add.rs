//! `pigeon domain add`, through the real binary.
//!
//! These exist because the ordering bug they cover was invisible at every level
//! below this one. The repository was correct, the key writer was correct, the
//! transaction was correct — and the command composed them in an order that
//! committed a domain whose private key did not exist.
//!
//! A failure here is a domain that cannot sign and a daemon that will not start,
//! so the tests drive the binary rather than the functions.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-cli-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join("keys"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        // The daemon owns migrations, so the database is created the same way
        // it would be — by migrating, not by hand.
        let db = dir.join("pigeon.db");
        let mut conn = pigeon_db::open(&db).expect("open");
        pigeon_db::migrate(&mut conn, &db).expect("migrate");

        Self { dir }
    }

    fn db(&self) -> PathBuf {
        self.dir.join("pigeon.db")
    }

    fn keys(&self) -> PathBuf {
        self.dir.join("keys")
    }

    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_pigeon"))
            .arg("--db")
            .arg(self.db())
            .args(args)
            .output()
            .expect("run pigeon");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn key_files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.keys())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Every domain, with the key file its row points at.
    fn recorded(&self) -> Vec<(String, String)> {
        let conn = pigeon_db::open_read_only(&self.db()).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT d.name, k.private_key_path FROM domain d
                 LEFT JOIN dkim_key k ON k.domain_id = d.id ORDER BY d.name",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            })
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    /// The invariant every test below asserts: every recorded key exists on
    /// disk, and derives the public key stored beside it.
    fn assert_keys_usable(&self) {
        let conn = pigeon_db::open_read_only(&self.db()).unwrap();
        for key in pigeon_db::repo::active_dkim_keys(&conn).unwrap() {
            let path = self.keys().join(&key.private_key_path);
            assert!(
                path.exists(),
                "{} records a key at {} that does not exist",
                key.domain,
                path.display()
            );
            let (derived, _) =
                pigeon_auth::dkim::inspect_private_file(&path).expect("read the recorded key");
            assert_eq!(
                derived, key.public_key,
                "{} records a public key its private key does not produce",
                key.domain
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(self.keys(), std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn adding_a_domain_leaves_a_usable_key() {
    let f = Fixture::new("add");
    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(ok, "{out}");
    assert!(out.contains("v=DKIM1; k=rsa; p="), "{out}");
    assert_eq!(f.key_files().len(), 1);
    f.assert_keys_usable();
}

#[test]
fn removing_and_re_adding_a_domain_produces_a_usable_key() {
    // The bug this file exists for.
    //
    // `domain remove` keeps the key file deliberately — it is the one piece of
    // state no backup of the database restores. With `{domain}.key` as the
    // name and the write *after* the commit, a later `domain add` for the same
    // name committed a new public key and then failed to write its private
    // half, because `create_new` correctly refused to clobber the old file.
    //
    // The domain was left recorded against a public key whose private half was
    // the previous key, and the daemon refused to start.
    let f = Fixture::new("readd");

    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(ok, "{out}");
    let first = f.key_files();
    assert_eq!(first.len(), 1);

    let (ok, out) = f.run(&["domain", "remove", "example.com", "--yes"]);
    assert!(ok, "{out}");
    assert_eq!(
        f.key_files(),
        first,
        "removing a domain deleted its private key"
    );

    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(ok, "re-adding a removed domain failed: {out}");

    // Two files now: the orphan and the new one, under different names.
    assert_eq!(f.key_files().len(), 2, "{:?}", f.key_files());
    f.assert_keys_usable();

    // And the row points at the new one, not the retained orphan.
    let recorded = f.recorded();
    assert_eq!(recorded.len(), 1);
    assert_ne!(
        recorded[0].1, first[0],
        "the re-added domain was recorded against the previous key file"
    );
}

#[cfg(unix)]
#[test]
fn a_key_that_cannot_be_written_leaves_no_domain_behind() {
    // The general case of the same ordering. Any write or fsync failure —
    // a full disk, a read-only mount, a permission change — must not leave a
    // committed domain with no usable key.
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new("nowrite");
    std::fs::set_permissions(f.keys(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(
        !ok,
        "a domain was added despite the key being unwritable: {out}"
    );

    std::fs::set_permissions(f.keys(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        f.recorded().is_empty(),
        "a domain was committed without a key: {:?}",
        f.recorded()
    );
    assert!(f.key_files().is_empty());
}

#[test]
fn a_refused_mutation_leaves_no_key_file_behind() {
    // The other half of the ordering: the key is written before the
    // transaction, so a transaction that rolls back must take the file with it
    // or the command leaves private key material for a domain that does not
    // exist.
    let f = Fixture::new("rollback");
    let (ok, _) = f.run(&["domain", "add", "example.com"]);
    assert!(ok);
    let after_first = f.key_files();

    // The same domain again: `add_domain` refuses, so the transaction never
    // commits.
    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(!ok, "a duplicate domain was accepted: {out}");
    assert_eq!(
        f.key_files(),
        after_first,
        "a refused command left a private key behind"
    );
    f.assert_keys_usable();
}

#[test]
fn a_dry_run_writes_neither_a_row_nor_a_key() {
    let f = Fixture::new("dryrun");
    let (ok, out) = f.run(&["--dry-run", "domain", "add", "example.com"]);
    assert!(ok, "{out}");
    assert!(f.recorded().is_empty(), "a dry run committed a domain");
    assert!(f.key_files().is_empty(), "a dry run wrote a private key");
}

#[cfg(unix)]
#[test]
fn the_private_key_is_not_readable_by_anyone_else() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new("mode");
    let (ok, out) = f.run(&["domain", "add", "example.com"]);
    assert!(ok, "{out}");

    let name = &f.key_files()[0];
    let mode = std::fs::metadata(f.keys().join(name))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "key is {mode:04o}");
}

#[test]
fn the_printed_record_is_the_one_that_was_stored() {
    // A record that does not match the stored public key is a record that
    // publishes a key nothing signs with.
    let f = Fixture::new("record");
    let (ok, out) = f.run(&["domain", "add", "example.com", "--json"]);
    assert!(ok, "{out}");

    let json: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    let printed = json["dkim"]["record_value"].as_str().unwrap();

    let conn = pigeon_db::open_read_only(&f.db()).unwrap();
    let keys = pigeon_db::repo::active_dkim_keys(&conn).unwrap();
    assert_eq!(printed, pigeon_auth::dkim::txt_record(&keys[0].public_key));

    let path: &str = json["dkim"]["private_key"].as_str().unwrap();
    assert!(
        Path::new(path).exists(),
        "the reported key path does not exist"
    );
}
