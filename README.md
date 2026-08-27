# Pigeon

**Self-hosted email forwarding for your domains.**

Pigeon receives mail for the domains you own, resolves aliases and catch-all rules, and forwards messages to the mailboxes you already use. It can also send on behalf of those domains over authenticated SMTP submission.

It is built around a simple idea:

**one binary, one SQLite database, your server, your DNS.**

No dashboard. No control plane. No hosted dependency. No telemetry.

---

## Why

Running several domains usually means maintaining addresses like:

```text
hello@example.com
security@example.com
billing@example.com
anything@anotherdomain.com
```

Hosted forwarding services do this well, and they do it on their infrastructure, under their limits, with your mail passing through their systems. Pigeon does the same job on a machine you control.

Configuration lives in SQLite and is managed entirely through the `pigeon` command. There is no web interface to maintain and no external database to operate.

---

## Features

**Inbound forwarding**

- Multiple domains on one host
- Unlimited aliases
- Exact, wildcard and reject rules
- Plus-addressing (`hello+tag@` routes through `hello@`)
- Multiple destinations per alias
- Per-domain default destination, inherited by aliases
- Bulk destination retargeting across domains
- Catch-all forwarding
- SRS envelope rewriting
- DKIM signature preservation
- ARC sealing
- Loop detection
- Delivery queue with retry and bounce handling

**Outbound sending**

- Authenticated submission on port 587
- Application credentials, not mailbox passwords
- Per-identity and per-domain send authorisation
- DKIM signing
- Direct-to-MX or upstream relay delivery
- Rate limits and abuse controls

**Operations**

- CLI-only management
- Headless daemon
- MX, SPF, DKIM, DMARC, PTR and TLS validation
- Route inspection without sending mail
- Email alerts when a domain is gated or recovers
- Structured logging
- IPv4 and IPv6
- systemd-friendly

---

## Architecture

```text
                     Internet
                        │
                        ▼
                ┌───────────────┐
                │    Pigeon     │
                │   SMTP/MX     │
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
                │ Route Engine  │
                └───────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
       Reject       Aliases       Catch-all
                        │             │
                        └──────┬──────┘
                               ▼
                     SRS · DKIM · ARC
                               │
                               ▼
                       Mail Forwarding
                               │
                               ▼
                    your existing mailbox
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

---

## Philosophy

Pigeon is intentionally small. It is not trying to become a mail platform.

It does not provide mailboxes, IMAP, POP3, webmail, user accounts, billing, teams, marketing email, newsletters, or analytics.

It does one job:

> Receive mail for a domain and forward it reliably. Send mail for a domain when explicitly authorised.

---

## Getting started

> **Not yet implemented.** Everything in this section describes the intended
> interface, not what a build does today. The `pigeon` command currently prints
> `not yet implemented` and exits; the CLI, SQLite control plane and DNS
> validation arrive in Milestones 1 and 5. What runs today is `pigeond`, which
> takes its entire configuration from environment variables. See
> [`docs/ROADMAP.md`](docs/ROADMAP.md) for what is actually built.

Every level of the CLI documents itself, and a bare noun prints its help rather than an error:

```bash
pigeon                    # overview
pigeon domain             # everything you can do to a domain
pigeon domain add --help  # one command, in detail
```

A working setup is three commands:

```bash
pigeon domain add example.com --to me@example.net
pigeon alias add example.com hello,hi,support
pigeon domain check example.com
```

Commands read `pigeon <noun> <verb> [target]`, and the verbs repeat — `list`, `add`, `remove`, `show`, `check`, `test` — so learning one noun teaches the rest. Full reference in [`docs/CLI.md`](docs/CLI.md).

### Add a domain

```bash
pigeon domain add example.com --to me@example.net
```

```text
Adding example.com...

✓ Domain created
✓ DKIM key generated

Required DNS configuration:

MX
  @       10 mx1.yourserver.net

TXT
  @       v=spf1 mx -all

TXT
  pigeon._domainkey
          v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFA...

TXT
  _dmarc  v=DMARC1; p=none; rua=mailto:dmarc@example.com

Domain status: PENDING_DNS

Run:

  pigeon domain check example.com
```

`mx1.yourserver.net` is the hostname of *your* Pigeon host. One server can carry mail for as many domains as you like — each domain simply points its MX at it.

### Publish the records, then validate

```bash
pigeon domain check example.com
```

```text
example.com

✓ MX
✓ SPF
✓ DKIM
✓ DMARC
✓ TLS

Domain ACTIVE.
```

When something is wrong, Pigeon tells you exactly what to change:

```text
example.com

✗ MX

Current:
  mx.old-provider.net

Expected:
  mx1.yourserver.net

Required:

  Type: MX
  Name: @
  Priority: 10
  Value: mx1.yourserver.net

Domain NOT READY.
```

A domain only becomes `ACTIVE` once every required check passes. There is no manual override.

### Run it

```bash
pigeon run
```

Or under systemd:

```bash
systemctl enable --now pigeond
pigeon status
```

---

## Aliases

A domain has one default destination, so the address you forward to is typed once rather than once per alias:

```bash
pigeon domain forward example.com me@example.net
pigeon alias add example.com hello
```

Several at a time:

```bash
pigeon alias add example.com hello,hi,support
```

```text
Added to example.com:

  hello@example.com    → me@example.net
  hi@example.com       → me@example.net
  support@example.com  → me@example.net

3 aliases using the domain default.
```

Override the destination where it differs, or fan one alias out:

```bash
pigeon alias add example.com billing --to finance@example.net
pigeon alias add example.com security --to a@example.net,b@example.net
```

Wildcards, for patterned addresses:

```bash
pigeon alias add example.com 'shop-*'
```

Reject rules, for addresses that should never be accepted:

```bash
pigeon alias add example.com postmaster-old --reject
```

Removal:

```bash
pigeon alias remove example.com hello
pigeon alias remove example.com hello,hi,support
pigeon alias remove example.com --all
```

### Plus-addressing

Enabled per domain and on by default. `hello+github@example.com` matches the `hello` alias, and the tag is preserved in the forwarded message so your destination mailbox can still filter on it.

---

## Catch-all

```bash
pigeon catchall add example.com
pigeon catchall add example.com --to me@example.net
pigeon catchall remove example.com
```

With catch-all on, any address that no alias claims is forwarded to the configured destination. Explicit aliases always win.

Catch-all is never enabled implicitly. A missing destination is an error, not a silent enable.

Catch-all and aliases work together rather than replacing each other — catch-all takes the long tail, while aliases route the addresses that go somewhere else, split between people, or get refused. If every alias on a domain points where the catch-all already points, Pigeon tells you they are redundant instead of leaving you to find out.

One thing to weigh: with catch-all on, every address on the domain is accepted at `RCPT TO`. Recipient rejection no longer applies, so dictionary attacks get `250` rather than `550` and spam volume rises. It is the right choice for a domain where every address should work, and a poor default for a domain with six real addresses.

---

## Destinations

Aliases are managed per domain. Destinations are the other axis — one mailbox receiving from many aliases across many domains.

```bash
pigeon destination list
```

```text
DESTINATION            ALIASES   DOMAINS   DEFAULT FOR
me@example.net             187        38            38
finance@example.net          4         2             -
old@previous.net            11         3             1
```

When a mailbox changes, repoint every use of it in one command:

```bash
pigeon destination replace old@previous.net me@example.net
```

It covers aliases, catch-all destinations and domain defaults, spans every domain unless `--domain` narrows it, and previews what it will change before doing anything.

`pigeon domain forward` is the same operation from the other side — one address across every domain, versus every alias on one domain — so it previews and confirms identically. Any command that changes more than you named shows you the list first.

## Route testing

Inspect how an address resolves without sending anything:

```bash
pigeon route inbound hello@example.com
```

```text
hello@example.com
      ↓
example.com
      ↓
alias: hello
      ↓
me@example.net

ACCEPT
```

```bash
pigeon route inbound unknown@example.com
```

```text
REJECT

Reason:
  alias not found
  catch-all disabled
```

---

## Outbound sending

Sending is deliberately separate from forwarding. An inbound alias grants no authority to send.

```text
alias:            billing@example.com → finance@example.net
sender identity:  hello@example.com
principal:        macbook-mail
```

`macbook-mail` can send as `hello@example.com` only if granted that identity. The `billing` alias does not imply it.

```bash
pigeon domain outbound example.com on
pigeon sender add example.com hello

pigeon auth create macbook-mail
pigeon auth allow macbook-mail hello@example.com
```

```text
Credential created.

Username: pg_7N...
Password: ********

The password is shown once. Store it securely.
```

Point any standard mail client at port 587 with STARTTLS. No Pigeon-specific protocol is required.

See [`docs/OUTBOUND.md`](docs/OUTBOUND.md).

---

## Checking everything

```bash
pigeon domains check
```

```text
Checking 42 domains...

40 healthy
1 warning
1 failed

FAILED

example.net
  ✗ MX points to mx.old-provider.net

WARNING

example.org
  ⚠ DMARC policy is p=none

Configuration check failed.
```

```bash
pigeon domains list
```

```text
DOMAIN              STATUS      ALIASES    CATCH-ALL   OUTBOUND
example.com         healthy          6          yes         yes
example.net         healthy          2           no          no
anotherdomain.io    warning          4          yes          no
project.dev         error            1           no          no
```

Singular commands act on one domain, plural on all of them. Every read command supports `--json`.

---

## Storage

```text
/etc/pigeon/
    pigeon.toml

/var/lib/pigeon/
    pigeon.db
    keys/
        example.com.key
        example.net.key

/var/spool/pigeon/

/var/log/pigeon/
    pigeon.log
```

SQLite holds domains, aliases, destinations, sender identities, credentials, DNS check state, queue metadata and delivery history. Message bodies never go in the database — they live in the spool, and are deleted once every recipient reaches a terminal state.

Private DKIM keys never leave the server. **They are the one piece of state you cannot regenerate**: lose them and every domain needs a new key published in DNS by hand. Back up `/var/lib/pigeon/` accordingly.

---

## Requirements

- A Linux server with a public IP
- TCP port 25 reachable inbound *and* permitted outbound
- Control over your DNS
- A hostname with matching forward and reverse DNS
- A TLS certificate
- A destination mailbox

Two things worth checking before you commit to a host. Many cloud providers block outbound port 25 by default, which rules out direct delivery. And a recycled IP may already be on a blocklist — check before building on it.

---

## Startup and domain gating

Pigeon validates its environment before accepting mail, and treats two kinds of failure differently.

**Local failures abort startup.** An unreadable database, a failed migration, an unwritable spool, invalid TLS configuration, a missing DKIM key for a signing domain, or a listener that will not bind. These are unambiguous misconfiguration.

**DNS failures gate a single domain.** A domain whose records regress moves to `ERROR` and stops accepting its own mail. The daemon still starts, and every other domain keeps working.

```text
Pigeon startup check

SYSTEM
  ✓ Database
  ✓ TLS certificate
  ✓ SMTP listener
  ✓ Hostname
  ✓ Reverse DNS

DOMAINS
  ✓ example.com
  ✓ example.net
  ✗ project.dev — MX record is incorrect

Started. 2 domains active, 1 gated.
```

This is deliberate: a resolver hiccup should never become a total mail outage across every domain on the host. Strictness belongs on the domain lifecycle, where nothing reaches `ACTIVE` without passing every check.

When a domain is gated while Pigeon is running, the operator is emailed — with what broke, what to publish, and the fact that mail is currently being refused. A recovery notice follows when it passes again.

```bash
pigeon domain notify example.com ops@example.net
pigeon alerts test
```

Alerts are sent from a dedicated identity on a domain you keep healthy, never from the failing domain itself — an alert about a broken DKIM record cannot be sent from the domain with the broken DKIM record. Test the path explicitly: when alerting breaks, the symptom is silence, which looks exactly like everything working.

See [`docs/ALERTING.md`](docs/ALERTING.md).

---

## Building

Pigeon is a Rust workspace.

```bash
cargo build --release
```

```text
crates/
  pigeon-types      core types, no I/O
  pigeon-config     bootstrap TOML
  pigeon-db         SQLite, migrations
  pigeon-dns        resolution and record validation
  pigeon-auth       DKIM, SPF, DMARC, ARC, SRS
  pigeon-route      routing snapshot and precedence
  pigeon-smtp       receiver state machine and delivery client
  pigeon-spool      durable spool, queue, retries
  pigeon-alert      operator notifications
  pigeon-testkit    test harness
  pigeond           the daemon
  pigeon-cli        the `pigeon` command
```

---

## Status

Under active development. The CLI and configuration model may change before the first stable release.

Do not use pre-release builds for mail you care about without keeping a fallback MX.

Roadmap: [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CLI reference](docs/CLI.md)
- [Outbound sending](docs/OUTBOUND.md)
- [Alerting](docs/ALERTING.md)
- [Security model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

---

## Contributing

Issues, bug reports, documentation improvements and pull requests are welcome.

Feedback is especially useful if you are running Pigeon in an unusual environment or carrying a large number of domains.

Contributions are accepted under the project licence.

---

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

---

**Pigeon**

*Your domains. Your server. Your mail routing.*
