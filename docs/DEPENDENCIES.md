# Dependencies

Every direct dependency, why it is here, and what it would take to remove it.
The list is short on purpose: a mail server is reachable by anyone, and each
crate here is code that runs against a stranger's bytes.

`cargo deny` enforces the bans in [deny.toml](../deny.toml) on every CI run —
advisories, licences, and a hard refusal of OpenSSL, native-tls and `aws-lc-rs`.

---

## What runs against untrusted input

These parse or process bytes an attacker controls. They get the most attention.

| Crate | Why | If it went away |
|---|---|---|
| `tokio` | the async runtime and every socket | nothing else is close for this shape of I/O |
| `mail-auth` | DKIM, ARC, SPF and DMARC | writing these is writing four specifications and their errata; not a trade worth making |
| `mail-parser` | MIME, for the parts `mail-auth` needs | comes with `mail-auth` |
| `rustls` + `tokio-rustls` | TLS | the alternative is OpenSSL, which `deny.toml` refuses |
| `rusqlite` (bundled SQLite) | the database | bundled rather than system: no version skew, one C dependency with no build-time discovery |
| `hickory-resolver` | DNS | needed for MX, TXT and PTR; the same resolver `mail-auth` uses, so "what did Pigeon ask DNS?" has one answer |
| `clap` | the CLI's argument parsing | only reachable from an operator's own shell |

## Cryptography

| Crate | Why |
|---|---|
| `ring` (through `rustls` and `mail-auth`) | every signature Pigeon makes or verifies |
| `argon2` | application credentials, and nothing else |
| `sha2`, `hmac`, `subtle` | SRS tags, and the constant-time comparison that keeps them from being guessed byte by byte |
| `zeroize` | wiping key material that would otherwise sit in freed memory |
| `rsa` | **key generation only.** Signing is `ring`'s. See below. |

### The `rsa` exception

`deny.toml` carries an advisory exception for RUSTSEC-2023-0071, a timing
sidechannel in `rsa`'s decryption path. It is allowed because `rsa` is used here
to *generate* DKIM keys and never to sign, decrypt or verify: a CI guard greps
for `decrypt`, `Pkcs1v15Encrypt` and `Oaep` across the workspace and fails if
any appears, and a second guard checks that `mail-auth` never resolves to `rsa`.

The exception ends if either guard has to be relaxed.

### `rustls-pemfile` is not here

It was, briefly. It is unmaintained (RUSTSEC-2025-0134) and its own repository
points at the PEM parsing inside `rustls-pki-types`, which is what this uses.

---

## Everything else

| Crate | Why |
|---|---|
| `serde` / `serde_json` / `toml` | configuration, and the `--json` CLI contract |
| `thiserror` / `anyhow` | error types; `thiserror` in libraries, `anyhow` only in the CLI |
| `tracing` / `tracing-subscriber` | structured logs |
| `libc` | `statvfs` for disk pressure, and the `setuid`/`setgid` calls that drop privilege |
| `getrandom` | credential and key material from the OS |
| `x509-parser` | certificate expiry, which rustls does not expose |
| `humantime-serde` | durations in the configuration file, written the way people write them |

## Test-only

`rcgen` generates the self-signed certificates the TLS tests need — a fixture
checked into the repository would expire. `libfuzzer-sys` and `arbitrary` are
the fuzzing harness, which lives in its own workspace so the stable CI gates do
not depend on nightly.

---

## Review policy

- **New dependencies need a reason in the pull request**, not just a line in
  `Cargo.toml`. The reason has to say what it does and why writing it is worse.
- **No crate that pulls OpenSSL, native-tls or `aws-lc-rs`.** Enforced by
  `deny.toml` and by a CI guard over the resolved tree.
- **No wildcard versions.** A dependency with no upper bound is a supply-chain
  decision deferred to whatever resolves next.
- **`cargo deny check` on every run**, including advisories. An advisory with an
  exception needs the exception written down here with the reason it is safe and
  the condition that would end it.
- **Prefer the standard library.** The base64 encoders in `pigeon-auth` and
  `pigeon-smtp` are thirty lines each, proved against RFC 4648's own vectors,
  and are not worth a dependency to review for ever.
