//! The Pigeon daemon.
//!
//! # Startup gating
//!
//! Two classes of failure, deliberately treated differently:
//!
//! **Local and unambiguous — abort startup.** Unreadable database, failed
//! migration, unwritable spool, invalid TLS configuration, missing DKIM private
//! key for a signing domain, listener that will not bind. These are
//! misconfiguration, and running half-configured is worse than not running.
//!
//! **Remote DNS state — gate the individual domain, keep serving.** A domain
//! whose records regressed moves to `Error` and stops accepting its own mail.
//! The daemon still starts and other domains are unaffected.
//!
//! The distinction matters: a resolver outage must not turn into a total mail
//! outage across every domain on the host. Strictness belongs on the domain
//! lifecycle — nothing reaches `Active` without passing every check — not on
//! process startup.

fn main() {
    eprintln!("pigeond: not yet implemented");
}
