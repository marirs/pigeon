# Pigeon

**Self-hosted email forwarding for your domains.**

Pigeon is a lightweight, headless mail forwarding service built for developers, indie founders, and small teams who want to manage inbound email across multiple domains without a dashboard, external control plane, or recurring hosted-service dependency.

It is designed around a simple idea:

**one binary, one SQLite database, your server, your DNS.**

Pigeon receives email for your domains, resolves aliases and catch-all rules, validates mail-related DNS configuration, and forwards messages to your existing inboxes.

---

## Why Pigeon?

Running multiple domains often means maintaining addresses such as:

```text
hello@example.com
security@example.com
billing@example.com
anything@anotherdomain.com
```

Pigeon lets you route all of them from your own infrastructure.

There is no web interface to maintain and no separate database server to operate.

Configuration is managed entirely through the CLI and stored locally in SQLite.

---

## Features

- Multiple domains
- Unlimited aliases
- Catch-all forwarding
- Multiple forwarding destinations
- SQLite-backed configuration
- CLI-only management
- Headless daemon
- DNS readiness checks
- MX validation
- SPF validation
- DKIM configuration checks
- DMARC validation
- TLS checks
- Forwarding route inspection
- Delivery queue and retry handling
- Local DKIM key management
- Loop detection
- Structured logging
- IPv4 and IPv6 support
- systemd-friendly operation
- No dashboard
- No telemetry
- No cloud dependency

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
                 ┌──────┴──────┐
                 │             │
                 ▼             ▼
              Aliases       Catch-all
                 │             │
                 └──────┬──────┘
                        │
                        ▼
                 Mail Forwarding
                        │
                        ▼
              Gmail / Proton / iCloud
              Outlook / Fastmail / etc.
```

---

## Philosophy

Pigeon is intentionally small.

It is not trying to become a full mail platform.

It does not provide:

- Mailboxes
- IMAP
- POP3
- Webmail
- User accounts
- Billing
- Teams
- Marketing email
- Newsletter delivery
- Analytics dashboards

Pigeon focuses on one job:

> Receive mail for a domain and forward it reliably.

---

## CLI

Pigeon is managed through the `pigeon` command.

### Add a domain

```bash
pigeon domain add example.com
```

Pigeon generates the required configuration and displays the DNS records that must be added.

Example:

```text
Adding example.com...

✓ Domain created
✓ DKIM key generated

Required DNS configuration:

MX
  @       10 mx1.pigeon.mx

TXT
  @       v=spf1 mx ~all

TXT
  pigeon._domainkey
          v=DKIM1; k=ed25519; p=...

TXT
  _dmarc
          v=DMARC1; p=none

Domain status: NOT READY

Run:

  pigeon domain check example.com
```

---

## Validate a Domain

```bash
pigeon domain check example.com
```

Example:

```text
example.com

✓ MX
✓ SPF
✓ DKIM
✓ DMARC
✓ TLS

Domain ACTIVE.
```

If something is wrong:

```text
example.com

✗ MX

Current:
  mx.old-provider.net

Expected:
  mx1.pigeon.mx

Required:

  Type: MX
  Name: @
  Priority: 10
  Value: mx1.pigeon.mx

Domain NOT READY.
```

---

## Check Everything

Pigeon includes a configuration test similar to other infrastructure tools.

```bash
pigeon check
```

Example:

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

This makes it easy to validate the entire installation after DNS or configuration changes.

---

## Domain Information

```bash
pigeon domain info example.com
```

Example:

```text
Domain: example.com

STATUS
  READY

MAIL ROUTING
  MX      mx1.pigeon.mx

AUTHENTICATION
  SPF     PASS
  DKIM    PASS
  DMARC   PASS

ALIASES

  hello@example.com
    → me@example.net

  security@example.com
    → security@example.net

CATCH-ALL
  enabled
  → me@example.net
```

---

## Aliases

Add an alias:

```bash
pigeon domain add-alias example.com hello me@example.net
```

Result:

```text
Added:

hello@example.com
→ me@example.net
```

Add another:

```bash
pigeon domain add-alias example.com security security@example.net
```

Remove an alias:

```bash
pigeon domain remove-alias example.com hello
```

Remove every alias from a domain:

```bash
pigeon domain remove-all-aliases example.com
```

---

## Catch-All

Enable catch-all forwarding:

```bash
pigeon domain catchall example.com enable me@example.net
```

Disable it:

```bash
pigeon domain catchall example.com disable
```

With catch-all enabled:

```text
anything@example.com
random@example.com
hello@example.com
```

can all be forwarded to the configured destination unless an explicit alias overrides the route.

---

## Test a Route

You can inspect how Pigeon would route an address without sending mail.

```bash
pigeon route test hello@example.com
```

Example:

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

Unknown address:

```bash
pigeon route test unknown@example.com
```

```text
REJECT

Reason:
  alias not found
  catch-all disabled
```

---

## List Domains

```bash
pigeon domain list
```

Example:

```text
DOMAIN              STATUS      ALIASES    CATCH-ALL
example.com         healthy          6          yes
example.net         healthy          2           no
anotherdomain.io    warning          4          yes
project.dev         error            1           no
```

---

## Run Pigeon

Start the daemon:

```bash
pigeon run
```

Or run it through systemd:

```bash
systemctl enable --now pigeond
```

Check status:

```bash
pigeon status
```

---

## Storage

Pigeon uses SQLite as its local source of truth.

A typical installation may look like:

```text
/etc/pigeon/
    pigeon.toml

/var/lib/pigeon/
    pigeon.db
    keys/
        example.com.key
        example.net.key

/var/log/pigeon/
    pigeon.log
```

The SQLite database stores information such as:

- Domains
- Aliases
- Destinations
- Catch-all rules
- DNS validation state
- Delivery queue
- Retry state
- Delivery history
- Runtime configuration

Private DKIM keys remain local to the server.

---

## DNS Validation

Pigeon can validate:

- MX records
- A / AAAA resolution
- SPF
- DKIM
- DMARC
- Reverse DNS
- TLS configuration

Run checks for all domains:

```bash
pigeon check
```

Or one domain:

```bash
pigeon domain check example.com
```

---

## Queued Mail

Inspect the delivery queue:

```bash
pigeon queue list
```

Retry queued messages:

```bash
pigeon queue retry
```

Retry one message:

```bash
pigeon queue retry <message-id>
```

Remove a queued item:

```bash
pigeon queue remove <message-id>
```

---

## Requirements

Pigeon is designed to run on a normal Linux server.

You will generally need:

- Linux
- A public IP address
- TCP port 25 available
- Control over your DNS records
- A hostname with valid forward and reverse DNS
- TLS certificate
- A destination mailbox

A single server can handle mail for many domains.

For higher availability, multiple MX nodes can be configured.

---

## Example DNS Layout

Pigeon server:

```text
mx1.pigeon.mx → 203.0.113.10
```

Your domain:

```text
example.com MX 10 mx1.pigeon.mx
```

Another domain:

```text
example.net MX 10 mx1.pigeon.mx
```

And another:

```text
project.dev MX 10 mx1.pigeon.mx
```

All domains can share the same Pigeon server.

---

## Security

Pigeon is intended to be conservative by default.

Planned and supported safeguards include:

- Strict recipient validation
- SMTP connection limits
- Rate limiting
- Message size limits
- Loop detection
- Bounce handling
- DNS validation
- Local DKIM key storage
- Safe forwarding rules
- TLS support
- Structured audit logs
- Atomic configuration changes
- SQLite transactions
- Safe startup validation

Pigeon should refuse to start when critical configuration is invalid.

---

## Startup Validation

Before accepting mail, Pigeon validates its runtime environment.

Example:

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
  ✗ project.dev

project.dev
  MX record is incorrect

Startup aborted.
```

Warnings may be reported without preventing startup.

Critical failures stop the daemon from accepting mail.

---

## Configuration Changes

CLI operations write directly to SQLite.

For example:

```bash
pigeon domain add-alias example.com accounts me@example.net
```

The running daemon can reload routing state without restarting.

Invalid updates should never replace the currently active configuration.

---

## Running Multiple MX Nodes

A future redundant installation may look like:

```text
example.com

MX 10 mx1.pigeon.mx
MX 20 mx2.pigeon.mx
```

Both nodes can provide inbound mail availability while sharing or replicating routing configuration.

A single-node installation remains the recommended starting point.

---

## Project Goals

Pigeon aims to remain:

**Small**

No unnecessary services or dependencies.

**Portable**

Run it on almost any VPS or dedicated Linux host.

**Understandable**

Mail routing should be inspectable from the CLI.

**Self-contained**

SQLite instead of an external database.

**Predictable**

Invalid configuration should fail clearly.

**Private**

No telemetry or external control plane.

**Developer-friendly**

If something is wrong, Pigeon should tell you exactly what is wrong and what needs to be changed.

---

## Roadmap

Early development priorities:

- [ ] SMTP receiver
- [ ] SQLite schema
- [ ] Domain management
- [ ] Alias management
- [ ] Catch-all routing
- [ ] DNS validation
- [ ] DKIM key generation
- [ ] SPF validation
- [ ] DMARC validation
- [ ] Mail forwarding
- [ ] Sender rewriting
- [ ] Retry queue
- [ ] Bounce handling
- [ ] Route testing
- [ ] Structured logging
- [ ] systemd service
- [ ] Docker image
- [ ] Multi-MX support
- [ ] Metrics endpoint
- [ ] Packaging for common Linux distributions

---

## Status

Pigeon is currently under development.

The CLI and configuration model may change before the first stable release.

Do not use pre-release builds for critical mail without maintaining a fallback MX path.

---

## Website

[pigeon.mx](https://pigeon.mx)

---

## License

Pigeon is open source.

License details will be added before the first public release.

---

## Contributing

Issues, bug reports, documentation improvements, and pull requests are welcome.

If you are running Pigeon in an unusual environment or managing a large number of domains, feedback is especially useful.

---

**Pigeon**

*Your domains. Your server. Your mail routing.*