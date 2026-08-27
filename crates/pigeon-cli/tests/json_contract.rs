//! The `--json` contract, enforced against the real binary.
//!
//! Every assertion here is about the *contract* rather than about any one
//! command's fields: exactly one JSON value on stdout, nothing else on stdout,
//! `format_version` and `error` always present, `null` rather than omitted,
//! deterministic ordering. A command that breaks one of those breaks every
//! consumer at once, which is why they are tested as rules over all commands
//! rather than as expectations per command.
//!
//! Driven through the binary because the contract *is* the process boundary.
//! Testing the functions that build the values would leave the two things a
//! consumer actually depends on — which stream, and how many values — unchecked.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

struct Cli {
    dir: PathBuf,
}

struct Output {
    stdout: String,
    stderr: String,
    success: bool,
}

impl Output {
    /// Parse stdout, asserting it holds exactly one JSON value and nothing else.
    fn json(&self, what: &str) -> Value {
        let mut de = serde_json::Deserializer::from_str(&self.stdout).into_iter::<Value>();
        let first = de
            .next()
            .unwrap_or_else(|| panic!("{what}: stdout held no JSON value: {:?}", self.stdout))
            .unwrap_or_else(|e| panic!("{what}: stdout is not JSON ({e}): {:?}", self.stdout));

        assert!(
            de.next().is_none(),
            "{what}: stdout held more than one JSON value: {:?}",
            self.stdout
        );

        let obj = first
            .as_object()
            .unwrap_or_else(|| panic!("{what}: response is not an object: {first}"));
        assert_eq!(
            obj.get("format_version"),
            Some(&Value::from(1)),
            "{what}: missing or wrong format_version"
        );
        assert!(
            obj.contains_key("error"),
            "{what}: `error` is absent; it must be null on success"
        );
        first
    }
}

impl Cli {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pigeon-json-{tag}-{}-{}",
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

    fn run(&self, args: &[&str]) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_pigeon"))
            .arg("--db")
            .arg(self.dir.join("pigeon.db"))
            .args(args)
            .output()
            .expect("run pigeon");
        Output {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            success: out.status.success(),
        }
    }

    fn json(&self, args: &[&str]) -> Value {
        let mut with_json: Vec<&str> = args.to_vec();
        with_json.push("--json");
        let out = self.run(&with_json);
        out.json(&args.join(" "))
    }

    /// A database with something in it, for the listing tests.
    fn populated(tag: &str) -> Self {
        let cli = Self::new(tag);
        cli.run(&["domain", "add", "example.com", "--to", "me@example.net"]);
        cli.run(&["alias", "add", "example.com", "hello,hi"]);
        cli.run(&[
            "alias",
            "add",
            "example.com",
            "billing",
            "--to",
            "f@example.net",
        ]);
        cli.run(&["alias", "add", "example.com", "old", "--reject"]);
        cli
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Every command that produces JSON, with arguments that succeed.
fn every_reading_command() -> Vec<Vec<&'static str>> {
    vec![
        vec!["domains", "list"],
        vec!["domain", "show", "example.com"],
        vec!["alias", "list", "example.com"],
        vec!["destination", "list"],
        vec!["route", "inbound", "hello@example.com"],
    ]
}

// ------------------------------------------------------- the contract itself

#[test]
fn every_command_emits_exactly_one_envelope() {
    let cli = Cli::populated("envelope");
    for args in every_reading_command() {
        let v = cli.json(&args);
        assert_eq!(v["error"], Value::Null, "{args:?} reported an error");
    }
}

#[test]
fn a_failure_is_still_one_json_value_on_stdout() {
    // The rule that makes a consumer's life simple: parse stdout
    // unconditionally, branch on `error`. Without it, a failing run writes
    // nothing there and every caller needs a special case.
    let cli = Cli::new("failure");
    let out = cli.run(&["domain", "show", "nope.test", "--json"]);

    assert!(!out.success, "a missing domain reported success");
    let v = out.json("domain show nope.test");
    assert_eq!(v["error"]["code"], "no_such_domain");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nope.test"),
        "{v}"
    );
}

#[test]
fn error_codes_are_stable_names_not_prose() {
    // The human `message` is free to be rewritten; `code` is the part a script
    // matches on, so it is asserted by value.
    let cli = Cli::populated("codes");

    let cases = [
        (vec!["domain", "show", "nope.test"], "no_such_domain"),
        (vec!["domain", "add", "example.com"], "domain_exists"),
        (vec!["alias", "add", "example.com", "hello"], "alias_exists"),
        (
            vec!["alias", "add", "example.com", "x", "--to", "not-an-address"],
            "invalid_address",
        ),
        (
            vec!["domain", "remove", "example.com"],
            "confirmation_required",
        ),
    ];

    for (args, code) in cases {
        let v = cli.json(&args);
        assert_eq!(v["error"]["code"], code, "{args:?} gave {v}");
    }
}

#[test]
fn a_configuration_a_command_would_break_reports_its_own_code() {
    // The enforcement boundary, seen from a consumer: this is the one a script
    // most needs to distinguish, because retrying will not help.
    let cli = Cli::populated("invalid");
    let v = cli.json(&[
        "alias",
        "add",
        "example.com",
        "loop",
        "--to",
        "loop@example.com",
    ]);
    assert_eq!(v["error"]["code"], "invalid_configuration", "{v}");
}

#[test]
fn nothing_but_json_reaches_stdout() {
    // Notes, warnings and progress belong on stderr, where they cannot corrupt
    // the parse. `route inbound` is the sharpest case: it has a standing caveat
    // that must be said and must not be in the value.
    let cli = Cli::populated("streams");
    let out = cli.run(&["route", "inbound", "hello@example.com", "--json"]);

    out.json("route inbound");
    assert!(
        out.stdout.trim().lines().count() == 1,
        "stdout was more than one line: {:?}",
        out.stdout
    );
    assert!(
        out.stderr.contains("does not yet route from this table"),
        "the caveat was dropped under --json rather than moved to stderr: {:?}",
        out.stderr
    );
}

#[test]
fn notes_move_to_stderr_rather_than_disappearing() {
    // A mutating command's advice is worth as much to a script's operator as to
    // a person. Under --json it goes to stderr; it must not simply vanish.
    let cli = Cli::populated("notes");
    let out = cli.run(&["alias", "add", "example.com", "fresh", "--json"]);

    out.json("alias add");
    assert!(
        out.stderr.contains("will not see this until it restarts"),
        "the reload note vanished under --json: {:?}",
        out.stderr
    );
}

#[test]
fn a_report_appears_as_data_and_as_prose() {
    // Structured for the script, human for the operator, and neither at the
    // expense of the other.
    let cli = Cli::populated("reports");
    cli.run(&["catchall", "add", "example.com", "--to", "me@example.net"]);

    let out = cli.run(&[
        "alias",
        "add",
        "example.com",
        "same",
        "--to",
        "me@example.net",
        "--json",
    ]);
    let v = out.json("alias add");

    let reports = v["reports"].as_array().expect("reports is an array");
    assert!(
        reports
            .iter()
            .any(|r| r["kind"] == "redundant_against_catchall"),
        "{v}"
    );
    assert!(
        out.stderr.contains("does not change where mail goes"),
        "{:?}",
        out.stderr
    );
}

// ------------------------------------------------------- null versus omitted

#[test]
fn an_absent_value_is_null_and_the_key_is_present() {
    // The rule that makes `format_version` mean something: a missing key can
    // only mean "this build has no such field", so an absent *value* has to be
    // spelled `null`.
    let cli = Cli::new("nulls");
    cli.run(&["domain", "add", "bare.test"]);

    let v = cli.json(&["domain", "show", "bare.test"]);
    assert!(
        v.as_object().unwrap().contains_key("default_destination"),
        "the key was omitted rather than null: {v}"
    );
    assert_eq!(v["default_destination"], Value::Null);

    // And a route that matched nothing still carries both fields.
    let v = cli.json(&["route", "inbound", "nobody@bare.test"]);
    for key in ["tier", "matched"] {
        assert!(
            v.as_object().unwrap().contains_key(key),
            "{key} omitted: {v}"
        );
        assert_eq!(v[key], Value::Null, "{key} should be null: {v}");
    }
}

#[test]
fn empty_collections_are_arrays_not_null() {
    let cli = Cli::new("empty");
    cli.run(&["domain", "add", "bare.test"]);

    let v = cli.json(&["alias", "list", "bare.test"]);
    assert_eq!(v["aliases"], Value::Array(vec![]), "{v}");

    let v = cli.json(&["destination", "list"]);
    assert_eq!(v["destinations"], Value::Array(vec![]), "{v}");

    // And on a database with no domains at all.
    let empty = Cli::new("empty2");
    let v = empty.json(&["domains", "list"]);
    assert_eq!(v["domains"], Value::Array(vec![]), "{v}");
}

// ------------------------------------------------------------- determinism

#[test]
fn the_same_database_produces_byte_identical_output() {
    // Ordering is part of the contract: a consumer diffing two runs, or caching
    // a response, must not see churn that means nothing.
    let cli = Cli::populated("determinism");
    for args in every_reading_command() {
        let mut with_json: Vec<&str> = args.clone();
        with_json.push("--json");

        let first = cli.run(&with_json).stdout;
        for _ in 0..3 {
            assert_eq!(
                cli.run(&with_json).stdout,
                first,
                "{args:?} is not deterministic"
            );
        }
    }
}

#[test]
fn object_keys_come_out_sorted() {
    // Not an accident worth relying on silently: serde_json's map is ordered,
    // and this asserts it so a future `preserve_order` feature cannot quietly
    // change the bytes every consumer sees.
    let cli = Cli::populated("keys");
    let out = cli.run(&["domain", "show", "example.com", "--json"]);
    let v = out.json("domain show");

    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(
        keys, sorted,
        "object keys are not in sorted order: {keys:?}"
    );
}

#[test]
fn lists_are_sorted_by_a_stated_key() {
    let cli = Cli::populated("sorted");

    let v = cli.json(&["alias", "list", "example.com"]);
    let patterns: Vec<&str> = v["aliases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["pattern"].as_str().unwrap())
        .collect();
    let mut sorted = patterns.clone();
    sorted.sort();
    assert_eq!(patterns, sorted, "aliases are not sorted by pattern");

    cli.run(&["domain", "add", "aaa.test"]);
    cli.run(&["domain", "add", "zzz.test"]);
    let v = cli.json(&["domains", "list"]);
    let names: Vec<&str> = v["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["domain"].as_str().unwrap())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "domains are not sorted by name");
}

// ------------------------------------------------------------- field shapes

#[test]
fn an_inheriting_alias_says_so_rather_than_leaving_it_to_be_inferred() {
    let cli = Cli::populated("inherits");
    let v = cli.json(&["alias", "list", "example.com"]);

    let by_pattern = |name: &str| -> Value {
        v["aliases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["pattern"] == name)
            .unwrap_or_else(|| panic!("no alias {name} in {v}"))
            .clone()
    };

    let hello = by_pattern("hello");
    assert_eq!(hello["inherits"], Value::Bool(true));
    assert_eq!(hello["destinations"], Value::Array(vec![]));
    assert_eq!(hello["reject"], Value::Bool(false));

    let billing = by_pattern("billing");
    assert_eq!(billing["inherits"], Value::Bool(false));
    assert_eq!(billing["destinations"][0], "f@example.net");

    let old = by_pattern("old");
    assert_eq!(old["reject"], Value::Bool(true));
    assert_eq!(old["inherits"], Value::Bool(false));
}

#[test]
fn a_dry_run_reports_what_it_would_do_and_changes_nothing() {
    let cli = Cli::populated("dryrun");
    let before = cli.json(&["alias", "list", "example.com"]);

    let v = cli.json(&["--dry-run", "alias", "add", "example.com", "ghost"]);
    assert_eq!(v["error"], Value::Null, "{v}");

    let after = cli.json(&["alias", "list", "example.com"]);
    assert_eq!(
        before["aliases"], after["aliases"],
        "a dry run changed the database"
    );
}
