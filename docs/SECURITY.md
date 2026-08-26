# Security Model

## Security objectives

Pigeon must protect:

- mail confidentiality in transit
- DKIM private keys
- SMTP submission credentials
- relay credentials
- routing configuration
- queued message contents
- database integrity

And must prevent:

- open relay
- unauthorized sender impersonation
- alias manipulation
- mail loss
- credential leakage
- path traversal through spool metadata
- queue replay
- command injection
- SQL injection
- DNS validation confusion
- unsafe configuration activation

## Threat model

Assume:

- arbitrary internet hosts can connect to TCP/25
- attackers can send malformed SMTP and MIME
- attackers can spoof sender headers
- DNS may be temporarily inconsistent
- authenticated credentials can be stolen
- disk can fill
- process can crash between operations
- remote SMTP servers can behave incorrectly or maliciously

## Open relay prevention

This is a release-blocking property.

Inbound TCP/25 may only accept recipients belonging to an ACTIVE inbound-enabled Pigeon domain and a valid alias/catch-all route.

Submission TCP/587 may relay arbitrary destinations only after authentication and only when sender policy passes.

Tests must cover combinations of:

```text
unauthenticated + local recipient
unauthenticated + remote recipient
authenticated + unauthorized sender
authenticated + authorized sender
local sender + remote recipient
remote sender + remote recipient
```

## TLS

Submission:

- STARTTLS required by default
- no password authentication before TLS
- modern TLS configuration

Inbound MTA:

- opportunistic STARTTLS initially
- strict transport policies may be supported later

## Passwords

Submission passwords:

- high entropy
- shown once
- stored using an appropriate password hash
- constant-time comparison where applicable
- revocable
- rotatable

## Relay secrets

Avoid storing cleartext upstream relay passwords in normal SQLite rows.

Preferred options:

1. protected secret file referenced by identifier
2. OS secret facility
3. encrypted secret store with machine-held key

## DKIM keys

Permissions:

```text
owner: pigeon service account
mode: 0600
```

Private keys are never printed by normal CLI commands.

Backups containing private keys must be protected.

## SQLite

- parameterized queries only
- foreign keys enabled
- migrations transactional where possible
- filesystem permissions restrictive
- integrity check command
- no SQL constructed from email addresses/domain strings

## Spool

Spool filenames are generated identifiers, never raw sender/recipient text.

Messages should be created with restrictive permissions.

All path resolution stays inside configured spool roots.

## Privileges

Binding TCP/25 may require privilege.

Preferred deployment:

- systemd socket capabilities or `CAP_NET_BIND_SERVICE`
- run Pigeon as unprivileged dedicated user
- do not run full process as root

## Logging

Never log:

- SMTP AUTH passwords
- relay passwords
- DKIM private keys
- complete sensitive message bodies

Addresses and message metadata may still be sensitive and should be logged at an intentionally chosen level.

## DNS

DNS output is untrusted input.

Validation code must handle:

- malformed records
- huge record sets
- multiple TXT chunks
- CNAME behavior
- loops
- timeouts
- resolver failure

DNS failure must not automatically deactivate a previously healthy domain unless policy explicitly requires it. Temporary DNS outage should not cause unnecessary service failure.

## Rate limits

Inbound:

- connections/IP
- commands/connection
- recipients/message
- message size
- concurrent connections

Submission:

- login attempts
- messages/principal
- recipients/principal
- concurrent connections
- optional daily caps

## Queue safety

Queue ownership uses leases.

A worker may not permanently hide a message simply because it crashed while DELIVERING.

Retries must be idempotent to the extent possible, while acknowledging that SMTP cannot guarantee exactly-once end-to-end delivery.

## Startup validation

Critical local failures stop startup:

- unreadable database
- failed migration
- missing private key for active signing domain
- invalid listener configuration
- unusable spool
- invalid TLS config for required submission

Temporary external DNS issues should normally degrade checks rather than destroy runtime state.

## Security release gate

A stable release should not ship until:

- anti-open-relay integration suite passes
- SMTP parser fuzzing exists
- queue crash tests pass
- credential redaction tests pass
- sender authorization tests pass
- dependency audit passes
- threat model reviewed
