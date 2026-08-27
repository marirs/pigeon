//! Loading a configuration out of the real schema and routing against it.
//!
//! The unit tests build snapshots from structs, which proves the precedence
//! logic and nothing about the SQL. This goes through migration 1 — the same
//! bytes that ship — so the column names, the join, and the meaning of
//! `catchall_enabled` are exercised rather than assumed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use pigeon_route::{Decision, Snapshot};
use pigeon_types::Address;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "pigeon-route-rt-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn db(&self) -> PathBuf {
        self.0.join("pigeon.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn migrated(tag: &str) -> (TempDir, rusqlite::Connection) {
    let tmp = TempDir::new(tag);
    let mut conn = pigeon_db::open(&tmp.db()).expect("open");
    pigeon_db::migrate(&mut conn, &tmp.db()).expect("migrate");
    (tmp, conn)
}

fn route(snap: &Snapshot, address: &str) -> String {
    let a = Address::parse(address).expect("address");
    match snap.resolve(&a) {
        Decision::Forward {
            tier, destinations, ..
        } => format!(
            "{tier:?} -> {}",
            destinations
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        Decision::Reject { tier, .. } => format!("{tier:?} -> REJECT"),
        other => format!("{other:?}"),
    }
}

#[test]
fn a_configuration_written_to_sqlite_routes_as_written() {
    let (_tmp, conn) = migrated("full");

    conn.execute_batch(
        "INSERT INTO destination(local,domain) VALUES('me','example.net');       -- 1
         INSERT INTO destination(local,domain) VALUES('finance','example.net');  -- 2
         INSERT INTO destination(local,domain) VALUES('All','example.net');      -- 3

         INSERT INTO domain(name,status,default_destination_id,catchall_enabled,
                            catchall_destination_id,created_at,updated_at)
           VALUES('example.com','active',1,1,3,0,0);

         -- inherits the domain default
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'hello',0);
         -- its own destination
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'billing',0);
         INSERT INTO alias_destination(alias_id,destination_id) VALUES(2,2);
         -- a wildcard
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'shop-*',0);
         INSERT INTO alias_destination(alias_id,destination_id) VALUES(3,2);
         -- a reject
         INSERT INTO alias(domain_id,pattern,kind,created_at)
           VALUES(1,'postmaster-old','reject',0);",
    )
    .expect("fixture");

    let inputs = pigeon_route::load(&conn).expect("load");
    let snap = Snapshot::build(inputs).expect("build").snapshot;

    assert_eq!(
        route(&snap, "hello@example.com"),
        "ExactFull -> me@example.net",
        "inheritance did not resolve to the domain default"
    );
    assert_eq!(
        route(&snap, "billing@example.com"),
        "ExactFull -> finance@example.net",
        "an explicit destination was overwritten by the default"
    );
    assert_eq!(
        route(&snap, "shop-1@example.com"),
        "Wildcard -> finance@example.net"
    );
    assert_eq!(
        route(&snap, "postmaster-old@example.com"),
        "ExactFull -> REJECT"
    );

    // Catch-all, and the destination keeping the case it was stored with.
    assert_eq!(
        route(&snap, "anyone@example.com"),
        "CatchAll -> All@example.net"
    );

    // Plus-addressing, on by default in the schema.
    assert_eq!(
        route(&snap, "hello+github@example.com"),
        "ExactBase -> me@example.net"
    );

    assert_eq!(route(&snap, "hello@elsewhere.test"), "UnknownDomain");
}

#[test]
fn a_disabled_domain_loads_and_refuses() {
    let (_tmp, conn) = migrated("disabled");
    conn.execute_batch(
        "INSERT INTO destination(local,domain) VALUES('me','example.net');
         INSERT INTO domain(name,status,inbound_enabled,default_destination_id,created_at,updated_at)
           VALUES('example.com','active',0,1,0,0);
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'hello',0);",
    )
    .expect("fixture");

    let built = Snapshot::build(pigeon_route::load(&conn).expect("load")).expect("build");
    assert_eq!(
        route(&built.snapshot, "hello@example.com"),
        "DomainNotAccepting"
    );

    // Validated but switched off looks like a fault, so it is said out loud.
    assert!(
        built
            .reports
            .iter()
            .any(|r| matches!(r, pigeon_route::Report::ActiveButDisabled { .. })),
        "{:?}",
        built.reports
    );
}

#[test]
fn a_loop_stored_in_sqlite_is_refused_at_build() {
    // The schema cannot express this: it is a property of the graph, not a row.
    let (_tmp, conn) = migrated("loop");
    conn.execute_batch(
        "INSERT INTO destination(local,domain) VALUES('b','two.test');
         INSERT INTO destination(local,domain) VALUES('a','one.test');
         INSERT INTO domain(name,status,created_at,updated_at) VALUES('one.test','active',0,0);
         INSERT INTO domain(name,status,created_at,updated_at) VALUES('two.test','active',0,0);
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(1,'a',0);
         INSERT INTO alias_destination(alias_id,destination_id) VALUES(1,1);
         INSERT INTO alias(domain_id,pattern,created_at) VALUES(2,'b',0);
         INSERT INTO alias_destination(alias_id,destination_id) VALUES(2,2);",
    )
    .expect("fixture");

    let inputs = pigeon_route::load(&conn).expect("load");
    match Snapshot::build(inputs) {
        Err(pigeon_route::BuildError::Loop { .. }) => {}
        other => panic!("a loop stored in the database was published: {other:?}"),
    }
}

#[test]
fn a_status_the_binary_does_not_know_refuses_to_load() {
    // Guessing would either gate a live domain or ungate a broken one.
    //
    // Migration 1's CHECK stops this arriving through SQLite, so the database
    // here is built without it — which is the case that matters: a file
    // restored from elsewhere, or written by a newer build whose lifecycle has
    // a state this one has never heard of.
    let conn = rusqlite::Connection::open_in_memory().expect("memory db");
    conn.execute_batch(
        "CREATE TABLE destination(id INTEGER PRIMARY KEY, local TEXT NOT NULL,
             domain TEXT NOT NULL) STRICT;
         CREATE TABLE domain(
             id INTEGER PRIMARY KEY, name TEXT NOT NULL,
             status TEXT NOT NULL,               -- no CHECK, on purpose
             inbound_enabled INTEGER NOT NULL DEFAULT 1,
             outbound_enabled INTEGER NOT NULL DEFAULT 0,
             plus_addressing INTEGER NOT NULL DEFAULT 1,
             catchall_enabled INTEGER NOT NULL DEFAULT 0,
             default_destination_id INTEGER,
             catchall_destination_id INTEGER) STRICT;
         CREATE TABLE alias(id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL,
             pattern TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'forward') STRICT;
         CREATE TABLE alias_destination(alias_id INTEGER NOT NULL,
             destination_id INTEGER NOT NULL) STRICT;
         INSERT INTO domain(name,status) VALUES('example.com','suspended');",
    )
    .expect("fixture");

    match pigeon_route::load(&conn) {
        Err(pigeon_route::LoadError::UnknownStatus { status, domain }) => {
            assert_eq!(status, "suspended");
            assert_eq!(domain, "example.com");
        }
        other => panic!("an unrecognised status was guessed at: {other:?}"),
    }
}
