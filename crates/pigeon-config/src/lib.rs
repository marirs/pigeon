//! Bootstrap configuration.
//!
//! Only machine identity lives here: hostname, listener addresses, database and
//! spool paths, TLS material, and the SRS secret. Mail-domain configuration is
//! *not* in TOML — it lives in SQLite and changes through the CLI.
//!
//! Everything this crate validates is local and unambiguous, so a failure here
//! aborts startup (see `pigeond`).
//!
//! # The boundary
//!
//! If changing a value requires a restart, it belongs here. If it can take
//! effect on reload, it belongs in the `setting` table. That is the whole rule,
//! and it is why `alerts.identity` is here despite looking like mail
//! configuration: an alert identity that could be changed by the same commands
//! that change domains could be pointed at a domain under test, which is the
//! one thing `ALERTING.md` says it must never be.
//!
//! # What this crate does not do
//!
//! It does not check anything requiring the database or the network. Two of the
//! three startup cross-checks in `M1-SCHEMA.md` §5 need rows that do not exist
//! until migrations have run, and the third is DNS and must not abort startup
//! at all. Those live in `pigeond`, in the documented order.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub mod validate;

pub use validate::{Checked, ValidationError};

/// Everything that can go wrong loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} is not valid TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("{0}")]
    Invalid(#[from] ValidationError),
}

/// Machine identity and local paths.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Name used in the SMTP banner, in EHLO, and in `Received:` headers.
    ///
    /// Its forward and reverse DNS must agree with the sending address or
    /// receivers treat everything from this host as suspect. That check is
    /// remote, so it warns rather than aborting — see `pigeond`.
    pub hostname: String,

    pub database: PathBuf,
    pub spool: PathBuf,

    /// Root for DKIM private keys.
    ///
    /// `dkim_key.private_key_path` is stored per row, but a per-row path with
    /// no configured root would let a hand-edited row name any readable file.
    /// Stored paths are resolved against this and required to stay inside it.
    pub keys: PathBuf,

    /// Root for relay credentials, for the same reason as `keys`.
    ///
    /// `relay.secret_ref` is a name, not a path. Keeping the password out of
    /// the row solves nothing if the row can name `/etc/shadow`.
    pub secrets: PathBuf,

    /// The SRS signing secret.
    ///
    /// A file rather than a value here because it is a secret and this file is
    /// convenient to make readable. It must be stable across restarts: every
    /// bounce return path issued before a change stops verifying after it.
    pub srs_secret_file: PathBuf,

    #[serde(default)]
    pub smtp: Smtp,

    #[serde(default)]
    pub alerts: Alerts,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smtp {
    #[serde(default)]
    pub inbound: Inbound,
    #[serde(default)]
    pub submission: Submission,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    pub listen: SocketAddr,
}

impl Default for Inbound {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:25".parse().expect("literal"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    /// Absent means submission is not served at all, which is the Milestone 1
    /// state: the listener arrives in Milestone 7.
    #[serde(default)]
    pub listen: Option<SocketAddr>,

    /// Defaults to true, and `validate` refuses to turn it off.
    #[serde(default = "yes")]
    pub require_starttls: bool,

    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
}

impl Default for Submission {
    fn default() -> Self {
        Self {
            listen: None,
            require_starttls: true,
            tls_certificate: None,
            tls_private_key: None,
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    #[serde(default)]
    pub enabled: bool,

    /// The address alerts are sent *as*.
    ///
    /// Must not be on a domain this Pigeon manages. An alert about a broken
    /// DKIM record cannot be sent from the domain with the broken DKIM record —
    /// it is destroyed by the fault it exists to report, and the operator sees
    /// silence, which looks exactly like health. Checked against the database
    /// at startup, since config alone cannot know.
    pub identity: Option<String>,

    /// The global operator address.
    pub to: Option<String>,

    #[serde(default = "default_confirm_checks")]
    pub confirm_checks: u32,

    #[serde(default = "default_cooldown", with = "humantime_serde_compat")]
    pub cooldown: Duration,

    #[serde(default = "default_breaker")]
    pub breaker_threshold: f64,
}

impl Default for Alerts {
    fn default() -> Self {
        Self {
            enabled: false,
            identity: None,
            to: None,
            confirm_checks: default_confirm_checks(),
            cooldown: default_cooldown(),
            breaker_threshold: default_breaker(),
        }
    }
}

fn default_confirm_checks() -> u32 {
    3
}
fn default_cooldown() -> Duration {
    Duration::from_secs(6 * 3600)
}
fn default_breaker() -> f64 {
    0.5
}

/// `"6h"` and friends, without taking a dependency for four lines of parsing.
pub(crate) mod humantime_serde_compat {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let raw = String::deserialize(d)?;
        parse(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "expected a duration like \"30s\", \"10m\" or \"6h\", got {raw:?}"
            ))
        })
    }

    /// Accepts an integer with a single unit suffix.
    ///
    /// Deliberately narrow. A configuration file is read by people, and
    /// `"1h30m"` parsing while `"90 minutes"` does not is the sort of partial
    /// flexibility that reads as a bug when it fails.
    pub fn parse(raw: &str) -> Option<Duration> {
        let raw = raw.trim();
        let (digits, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit())?);
        let n: u64 = digits.parse().ok()?;
        let secs = match unit {
            "s" => n,
            "m" => n.checked_mul(60)?,
            "h" => n.checked_mul(3600)?,
            "d" => n.checked_mul(86_400)?,
            _ => return None,
        };
        Some(Duration::from_secs(secs))
    }
}

impl Config {
    /// Read and parse, without touching anything it names.
    ///
    /// Parsing and validation are separate so a caller can report "this file is
    /// not TOML" differently from "this path is not writable" — they have
    /// different fixes, and one of them is a typo.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Read, parse and validate in one step.
    pub fn load_and_validate(path: &Path) -> Result<Checked, ConfigError> {
        Ok(Self::load(path)?.validate()?)
    }

    /// Check everything local. See [`validate`].
    pub fn validate(self) -> Result<Checked, ValidationError> {
        validate::validate(self)
    }
}
