//! Bulk import, through the real binary.
//!
//! `M1-IMPORT.md` §7 names twelve properties and the mutations that must break
//! them. The ones that matter most are about what is left behind when an import
//! does *not* succeed: rows, keys, or neither.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-import-{tag}-{}-{}",
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

    fn csv(&self, name: &str, body: &str) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_pigeon"))
            .arg("--db")
            .arg(self.db())
            .args(args)
            .output()
            .expect("run pigeon");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut v: Vec<&str> = args.to_vec();
        v.push("--json");
        let (_, stdout, _) = self.run(&v);
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e}): {stdout:?}"))
    }

    fn import(&self, file: &Path, extra: &[&str]) -> (bool, String, String) {
        let mut args: Vec<String> = vec!["import".into(), "csv".into(), file.display().to_string()];
        args.extend(extra.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(&refs)
    }

    fn key_count(&self) -> usize {
        std::fs::read_dir(self.keys()).unwrap().count()
    }

    fn domain_count(&self) -> i64 {
        let conn = pigeon_db::open_read_only(&self.db()).unwrap();
        conn.query_row("SELECT count(*) FROM domain", [], |r| r.get(0))
            .unwrap()
    }

    fn aliases(&self, domain: &str) -> Vec<pigeon_db::repo::AliasSummary> {
        let conn = pigeon_db::open_read_only(&self.db()).unwrap();
        pigeon_db::repo::list_aliases(&conn, domain).unwrap_or_default()
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

const GOOD: &str = "\
address,destination
hello@example.com,me@example.net
support@example.com,me@example.net
support@example.com,ops@example.net
";

// ------------------------------------------------------- nothing left behind

#[test]
fn one_bad_row_anywhere_leaves_nothing_behind() {
    // Parsing is cheap and reversible; row three hundred is neither.
    let f = Fixture::new("badrow");
    let mut body = String::from("address,destination\n");
    for i in 0..400 {
        body.push_str(&format!("a{i}@example.com,me@example.net\n"));
    }
    body.push_str("broken-no-at-sign,me@example.net\n");
    let file = f.csv("big.csv", &body);

    let (ok, _, err) = f.import(&file, &[]);
    assert!(!ok, "an import with a bad row reported success");
    assert!(err.contains("row 402"), "the row number is wrong: {err}");
    assert_eq!(f.domain_count(), 0, "rows survived a refused import");
    assert_eq!(f.key_count(), 0, "keys survived a refused import");
}

#[test]
fn every_conflict_is_reported_not_the_first() {
    // An import that fails on row 12, is corrected, then fails on row 19 is an
    // afternoon.
    let f = Fixture::new("allconflicts");
    let file = f.csv(
        "many.csv",
        "address,destination\n\
         no-at-sign,me@example.net\n\
         ok@example.com,not-an-address\n\
         blank@example.com,\n",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["error"]["code"], "import_conflicts", "{v}");
    let conflicts = v["conflicts"].as_array().unwrap();
    assert_eq!(conflicts.len(), 3, "only some conflicts were reported: {v}");

    let kinds: Vec<&str> = conflicts
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"invalid_address"), "{kinds:?}");
    assert!(kinds.contains(&"invalid_destination"), "{kinds:?}");
    assert!(kinds.contains(&"forward_without_destination"), "{kinds:?}");
}

#[cfg(unix)]
#[test]
fn keys_are_written_before_rows() {
    // An unwritable keys directory must stop the import before anything is
    // committed. The reverse ordering leaves forty domains that cannot sign.
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new("keysfirst");
    let file = f.csv("a.csv", GOOD);
    std::fs::set_permissions(f.keys(), std::fs::Permissions::from_mode(0o500)).unwrap();

    let (ok, _, _) = f.import(&file, &[]);
    assert!(!ok, "an import succeeded with an unwritable keys directory");

    std::fs::set_permissions(f.keys(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.domain_count(), 0, "rows were committed without keys");
}

#[test]
fn a_rolled_back_import_removes_the_keys_it_wrote() {
    // A loop between two imported rows: both individually valid, and only the
    // snapshot built from both can see it. The keys are already on disk by
    // then, so cleanup is what stops private key material being left behind.
    let f = Fixture::new("cleanup");
    let file = f.csv(
        "loop.csv",
        "address,destination\n\
         a@one.test,b@two.test\n\
         b@two.test,a@one.test\n",
    );

    let (ok, _, err) = f.import(&file, &[]);
    assert!(!ok, "a loop between imported rows was accepted: {err}");
    assert_eq!(f.domain_count(), 0);
    assert_eq!(
        f.key_count(),
        0,
        "a rolled-back import left its keys behind"
    );
}

// ------------------------------------------------------ merge versus replace

#[test]
fn existing_aliases_require_the_flag() {
    let f = Fixture::new("moderequired");
    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &[]).0);

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["error"]["code"], "mode_required", "{v}");
}

#[test]
fn a_catch_all_alone_requires_the_flag() {
    // The case an "existing aliases" test waves through. `--replace` removes
    // catch-alls, so a domain holding only one is exactly the domain that would
    // silently lose the rule accepting every address on it.
    let f = Fixture::new("catchallflag");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    f.run(&["catchall", "add", "example.com", "--to", "all@example.net"]);
    assert!(
        f.aliases("example.com").is_empty(),
        "the domain has aliases"
    );

    let file = f.csv("a.csv", GOOD);
    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["error"]["code"], "mode_required", "{v}");

    let domains = v["domains"].as_array().unwrap();
    assert_eq!(domains[0]["aliases"], 0);
    assert_eq!(domains[0]["catchall"], true, "{v}");
}

#[test]
fn replace_needs_confirmation() {
    let f = Fixture::new("confirm");
    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &[]).0);

    let v = f.json(&["import", "csv", &file.display().to_string(), "--replace"]);
    assert_eq!(v["error"]["code"], "confirmation_required", "{v}");
}

#[test]
fn replace_removes_the_catch_all_and_keeps_the_default() {
    // Ruling I-1. A catch-all is routing the file expresses; a default is
    // policy the file cannot set, so removing it would delete something the
    // import has no way to restore.
    let f = Fixture::new("replacescope");
    f.run(&["domain", "add", "example.com", "--to", "keepme@example.net"]);
    f.run(&["catchall", "add", "example.com", "--to", "all@example.net"]);
    f.run(&["alias", "add", "example.com", "gone"]);

    let file = f.csv("a.csv", GOOD);
    let (ok, _, err) = f.import(&file, &["--replace", "--yes"]);
    assert!(ok, "{err}");

    let patterns: Vec<String> = f
        .aliases("example.com")
        .into_iter()
        .map(|a| a.pattern)
        .collect();
    assert!(!patterns.contains(&"gone".to_string()), "{patterns:?}");
    assert!(patterns.contains(&"hello".to_string()), "{patterns:?}");

    let v = f.json(&["domain", "show", "example.com"]);
    assert_eq!(v["catchall"], false, "the catch-all survived --replace");
    assert_eq!(
        v["default_destination"], "keepme@example.net",
        "--replace removed the domain default"
    );
}

#[test]
fn replace_is_scoped_to_the_files_own_domains() {
    let f = Fixture::new("scoped");
    f.run(&["domain", "add", "other.test", "--to", "me@example.net"]);
    f.run(&["alias", "add", "other.test", "untouched"]);

    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &["--replace", "--yes"]).0);

    let patterns: Vec<String> = f
        .aliases("other.test")
        .into_iter()
        .map(|a| a.pattern)
        .collect();
    assert_eq!(
        patterns,
        vec!["untouched".to_string()],
        "--replace reached a domain the file never named"
    );
}

#[test]
fn merge_keeps_what_is_already_there() {
    let f = Fixture::new("merge");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    f.run(&["alias", "add", "example.com", "kept"]);

    let file = f.csv("a.csv", GOOD);
    let (ok, _, err) = f.import(&file, &["--merge"]);
    assert!(ok, "{err}");

    let patterns: Vec<String> = f
        .aliases("example.com")
        .into_iter()
        .map(|a| a.pattern)
        .collect();
    assert!(patterns.contains(&"kept".to_string()), "{patterns:?}");
    assert!(patterns.contains(&"hello".to_string()), "{patterns:?}");
}

#[test]
fn merge_refuses_an_alias_that_differs() {
    let f = Fixture::new("mergediff");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    f.run(&[
        "alias",
        "add",
        "example.com",
        "hello",
        "--to",
        "elsewhere@x.test",
    ]);

    let file = f.csv("a.csv", GOOD);
    let v = f.json(&["import", "csv", &file.display().to_string(), "--merge"]);
    assert_eq!(v["error"]["code"], "import_conflicts", "{v}");
    assert_eq!(v["conflicts"][0]["kind"], "existing_alias_differs", "{v}");
}

// ---------------------------------------------------------------- the format

#[test]
fn repeated_addresses_fan_out() {
    let f = Fixture::new("fanout");
    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &[]).0);

    let support = f
        .aliases("example.com")
        .into_iter()
        .find(|a| a.pattern == "support")
        .expect("support alias");
    assert_eq!(
        support.destinations,
        vec!["me@example.net".to_string(), "ops@example.net".to_string()]
    );
}

#[test]
fn a_repeated_address_with_a_different_kind_conflicts() {
    // Accumulating destinations is a union of forwards. A row saying forward
    // and a row saying reject are two intentions, and picking either is a
    // guess.
    let f = Fixture::new("kindconflict");
    let file = f.csv(
        "a.csv",
        "address,destination,kind\n\
         hello@example.com,me@example.net,forward\n\
         hello@example.com,,reject\n",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "kind_conflict", "{v}");
    assert_eq!(f.domain_count(), 0);
}

#[test]
fn a_quoted_local_part_containing_a_semicolon_survives() {
    // Why the format is one destination per row. `"a;b"@example.com` is a legal
    // address that `Address::parse` accepts, so no delimiter inside a cell can
    // be unambiguous.
    let f = Fixture::new("semicolon");
    let file = f.csv(
        "a.csv",
        "address,destination\nhello@example.com,\"\"\"a;b\"\"@example.net\"\n",
    );
    let (ok, _, err) = f.import(&file, &[]);
    assert!(ok, "{err}");

    let hello = f
        .aliases("example.com")
        .into_iter()
        .find(|a| a.pattern == "hello")
        .expect("hello");
    assert_eq!(
        hello.destinations,
        vec!["\"a;b\"@example.net".to_string()],
        "a quoted local part was split on its semicolon"
    );
}

#[test]
fn a_missing_header_row_is_refused() {
    // I-2. Column order varies between exporters, and guessing which column is
    // the destination imports every alias backwards.
    let f = Fixture::new("noheader");
    let file = f.csv("a.csv", "hello@example.com,me@example.net\n");

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "missing_header", "{v}");
    assert_eq!(f.domain_count(), 0);
}

#[test]
fn a_typo_in_the_header_is_reported_as_a_typo() {
    // Distinct from a missing header, because the fix is different: one means
    // add a row, the other means correct a word. Reporting the first cell of a
    // data row as an "unknown column" is accurate and useless.
    let f = Fixture::new("headertypo");
    let file = f.csv(
        "a.csv",
        "address,destinaton
hello@example.com,me@example.net
",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "unknown_column", "{v}");
    assert!(
        v["conflicts"][0]["message"]
            .as_str()
            .unwrap()
            .contains("destinaton"),
        "{v}"
    );
}

#[test]
fn column_order_does_not_matter() {
    let f = Fixture::new("colorder");
    let file = f.csv(
        "a.csv",
        "destination,address\nme@example.net,hello@example.com\n",
    );
    let (ok, _, err) = f.import(&file, &[]);
    assert!(ok, "{err}");
    assert_eq!(f.aliases("example.com")[0].pattern, "hello");
}

#[test]
fn a_catch_all_row_sets_the_catch_all() {
    let f = Fixture::new("catchallrow");
    let file = f.csv(
        "a.csv",
        "address,destination\n*@example.com,all@example.net\n",
    );
    assert!(f.import(&file, &[]).0);

    let v = f.json(&["domain", "show", "example.com"]);
    assert_eq!(v["catchall"], true, "{v}");
    assert!(
        f.aliases("example.com").is_empty(),
        "the catch-all became an alias"
    );
}

// ------------------------------------------------------------- state, keys

#[test]
fn an_existing_domain_keeps_its_state() {
    // Ruling I-3. Import adds routing; it is not a lifecycle operation, and
    // moving a live domain because a file mentioned it would stop its mail.
    let f = Fixture::new("state");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    {
        let conn = pigeon_db::open(&f.db()).unwrap();
        conn.execute("UPDATE domain SET status = 'active'", [])
            .unwrap();
    }
    f.run(&["domain", "disable", "example.com"]);

    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &["--merge"]).0);

    let v = f.json(&["domain", "show", "example.com"]);
    assert_eq!(v["status"], "active", "import moved the lifecycle state");
    assert_eq!(
        v["inbound_enabled"], false,
        "import re-enabled a disabled domain"
    );
    assert_eq!(v["default_destination"], "me@example.net");
}

#[test]
fn one_key_per_new_domain_and_none_for_existing_ones() {
    let f = Fixture::new("keycount");
    f.run(&["domain", "add", "already.test", "--to", "me@example.net"]);
    assert_eq!(f.key_count(), 1);

    let file = f.csv(
        "a.csv",
        "address,destination\n\
         a@one.test,me@example.net\n\
         b@two.test,me@example.net\n\
         c@already.test,me@example.net\n",
    );
    let (ok, _, err) = f.import(&file, &["--merge"]);
    assert!(ok, "{err}");

    // Two new domains, so two new keys; `already.test` keeps the one it had.
    assert_eq!(
        f.key_count(),
        3,
        "key count does not match new-domain count"
    );
}

#[test]
fn a_dry_run_writes_no_rows_and_no_keys() {
    let f = Fixture::new("dryrun");
    let file = f.csv("a.csv", GOOD);

    let (ok, _, err) = f.import(&file, &["--dry-run"]);
    assert!(ok, "{err}");
    assert_eq!(f.domain_count(), 0, "a dry run committed rows");
    assert_eq!(f.key_count(), 0, "a dry run generated keys");
}

#[test]
fn a_dry_run_reports_the_same_conflicts_a_real_run_would() {
    let f = Fixture::new("dryconflict");
    let file = f.csv(
        "a.csv",
        "address,destination\n\
         a@one.test,b@two.test\n\
         b@two.test,a@one.test\n",
    );
    let (ok, _, _) = f.import(&file, &["--dry-run"]);
    assert!(!ok, "a dry run of a looping import reported success");
}

#[test]
fn re_importing_the_same_file_changes_nothing() {
    let f = Fixture::new("reimport");
    let file = f.csv("a.csv", GOOD);
    assert!(f.import(&file, &[]).0);
    let before = f.aliases("example.com");

    let (ok, stdout, err) = f.import(&file, &["--merge", "--json"]);
    assert!(ok, "{err}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["aliases_created"], 0, "{v}");
    assert_eq!(v["aliases_unchanged"], 2, "{v}");
    assert_eq!(f.aliases("example.com"), before);
}

#[test]
fn the_json_response_follows_the_contract() {
    let f = Fixture::new("json");
    let file = f.csv("a.csv", GOOD);
    let v = f.json(&["import", "csv", &file.display().to_string()]);

    assert_eq!(v["format_version"], 1);
    assert_eq!(v["error"], Value::Null);
    assert_eq!(v["applied"], true);
    assert_eq!(v["mode"], "merge");
    assert_eq!(v["domains_created"], 1);
    assert_eq!(v["keys_generated"], 1);
    assert_eq!(
        v["conflicts"],
        Value::Array(vec![]),
        "conflicts must be [] not absent"
    );
}

// ------------------------------------------------- review findings, pinned

#[test]
fn a_reject_catch_all_is_refused() {
    // It became `catchall_enabled = 1` with no own destination, which forwards
    // via the domain default — turning a rule that says "refuse everything"
    // into one that accepts everything.
    let f = Fixture::new("rejectcatchall");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    let file = f.csv("a.csv", "address,destination,kind\n*@example.com,,reject\n");

    let v = f.json(&["import", "csv", &file.display().to_string(), "--merge"]);
    assert_eq!(v["conflicts"][0]["kind"], "reject_catchall", "{v}");

    let show = f.json(&["domain", "show", "example.com"]);
    assert_eq!(show["catchall"], false, "a reject row enabled a catch-all");
}

#[test]
fn a_catch_all_cannot_fan_out() {
    // Two rows silently became one destination, and which one depended on file
    // order.
    let f = Fixture::new("catchallfanout");
    let file = f.csv(
        "a.csv",
        "address,destination\n*@example.com,a@x.test\n*@example.com,b@x.test\n",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "catchall_fan_out", "{v}");
    assert_eq!(f.domain_count(), 0);
}

#[test]
fn merge_refuses_a_differing_catch_all_rather_than_overwriting_it() {
    // `--merge` promises to change nothing that is already there, and the
    // catch-all was the one rule it silently replaced.
    let f = Fixture::new("mergecatchall");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    f.run(&["catchall", "add", "example.com", "--to", "original@x.test"]);

    let file = f.csv(
        "a.csv",
        "address,destination\n*@example.com,different@x.test\n",
    );
    let v = f.json(&["import", "csv", &file.display().to_string(), "--merge"]);
    assert_eq!(v["conflicts"][0]["kind"], "existing_alias_differs", "{v}");

    let show = f.json(&["domain", "show", "example.com"]);
    assert_eq!(show["catchall"], true);
    let conn = pigeon_db::open_read_only(&f.db()).unwrap();
    let current: String = conn
        .query_row(
            "SELECT d.local || '@' || d.domain FROM domain dom
             JOIN destination d ON d.id = dom.catchall_destination_id
             WHERE dom.name = 'example.com'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(current, "original@x.test", "merge overwrote the catch-all");
}

#[test]
fn an_identical_catch_all_under_merge_is_unchanged() {
    let f = Fixture::new("samecatchall");
    f.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
    f.run(&["catchall", "add", "example.com", "--to", "same@x.test"]);

    let file = f.csv("a.csv", "address,destination\n*@example.com,same@x.test\n");
    let (ok, stdout, err) = f.import(&file, &["--merge", "--json"]);
    assert!(ok, "{err}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["aliases_unchanged"], 1, "{v}");
    assert_eq!(
        v["catchalls_set"], 0,
        "an identical catch-all was rewritten"
    );
}

#[test]
fn an_invalid_domain_is_refused_before_any_key_is_generated() {
    // It used to reach key generation and be caught by the snapshot — a minute
    // of work and a file on disk for a row the file could have been told about
    // immediately.
    let f = Fixture::new("baddomain");
    let file = f.csv(
        "a.csv",
        "address,destination\nhello@not_a_domain,me@x.test\nhello@no-dot,me@x.test\n",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    let kinds: Vec<&str> = v["conflicts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["invalid_domain", "invalid_domain"], "{v}");
    assert_eq!(
        f.key_count(),
        0,
        "a key was generated for an unusable domain"
    );
}

#[test]
fn malformed_quoting_is_refused_rather_than_rewritten() {
    // An unterminated quote used to be read as though it were not there, which
    // imports a different address than the file names.
    let f = Fixture::new("badquotes");

    let unterminated = f.csv(
        "a.csv",
        "address,destination\nhello@example.com,\"me@example.net\n",
    );
    let v = f.json(&["import", "csv", &unterminated.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "malformed_csv", "{v}");

    let inner = f.csv(
        "b.csv",
        "address,destination\nhello@example.com,me\"@example.net\n",
    );
    let v = f.json(&["import", "csv", &inner.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "malformed_csv", "{v}");

    assert_eq!(f.domain_count(), 0);
}

#[test]
fn a_duplicated_header_column_is_refused() {
    // Taking the first or the last is a coin toss over which column holds the
    // data, and the file gives no way to tell which the exporter meant.
    let f = Fixture::new("duphdr");
    let file = f.csv(
        "a.csv",
        "address,destination,destination\nhello@example.com,a@x.test,b@x.test\n",
    );
    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["conflicts"][0]["kind"], "duplicate_header", "{v}");
}

#[test]
fn a_real_run_snapshot_failure_reports_conflicts_not_a_generic_error() {
    // The loop between two imported rows is found inside the transaction, and
    // its failure has to have the same shape as one found in the file — the
    // contract promises a `conflicts` array for `import_conflicts`.
    let f = Fixture::new("realconflict");
    let file = f.csv(
        "a.csv",
        "address,destination\na@one.test,b@two.test\nb@two.test,a@one.test\n",
    );

    let v = f.json(&["import", "csv", &file.display().to_string()]);
    assert_eq!(v["error"]["code"], "import_conflicts", "{v}");
    assert_eq!(v["conflicts"][0]["kind"], "unserveable", "{v}");
    assert!(
        v["conflicts"][0]["message"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{v}"
    );
}

#[test]
fn a_dry_run_counts_only_the_aliases_it_would_create() {
    // `rule_count` counted catch-alls as aliases and counted rules already
    // present, so a dry run of a no-op import claimed it would create
    // everything in the file.
    let f = Fixture::new("dryruncount");
    let file = f.csv(
        "a.csv",
        "address,destination\nhello@example.com,me@example.net\n*@example.com,all@example.net\n",
    );
    assert!(f.import(&file, &[]).0);

    let (ok, stdout, err) = f.import(&file, &["--merge", "--dry-run", "--json"]);
    assert!(ok, "{err}");
    let v: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["aliases_created"], 0, "{v}");
    assert_eq!(v["aliases_unchanged"], 2, "{v}");
    assert_eq!(v["catchalls_set"], 1, "{v}");
}
