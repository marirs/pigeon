# CLI Reference

The public command is `pigeon`.

The daemon process/service may appear as `pigeond` at the operating-system level, but users should normally interact with `pigeon`.

## General

```bash
pigeon --help
pigeon --version
pigeon check
pigeon status
pigeon run
```

## Domain commands

```bash
pigeon domain list
pigeon domain add <domain>
pigeon domain remove <domain>
pigeon domain info <domain>
pigeon domain check <domain>
pigeon domain enable <domain>
pigeon domain disable <domain>
```

### Add

```bash
pigeon domain add example.com
```

Behavior:

1. normalize domain
2. reject duplicates
3. create domain row
4. create DKIM selector/key
5. render required DNS
6. mark PENDING_DNS
7. run initial DNS check

### Info

```bash
pigeon domain info example.com
```

Should show:

- lifecycle status
- inbound enabled
- outbound enabled
- delivery mode
- expected MX
- observed MX
- SPF state
- DKIM state
- DMARC state
- aliases
- catch-all
- sender identities
- queue summary
- last DNS check

### Check

```bash
pigeon domain check example.com
```

`--json` should be supported for automation:

```bash
pigeon domain check example.com --json
```

## Alias commands

```bash
pigeon domain aliases example.com
pigeon domain add-alias example.com hello you@example.net
pigeon domain remove-alias example.com hello
pigeon domain remove-all-aliases example.com
```

Multiple destinations:

```bash
pigeon domain add-alias example.com security a@example.net b@example.net
```

## Catch-all

```bash
pigeon domain catchall example.com enable you@example.net
pigeon domain catchall example.com disable
pigeon domain catchall example.com info
```

Catch-all must always be explicit. Missing alias arguments must never silently enable it.

## Sender identities

Outbound sending is separate from inbound aliases.

```bash
pigeon sender list example.com
pigeon sender add example.com hello
pigeon sender remove example.com hello
pigeon sender allow-all example.com
pigeon sender deny-all example.com
```

An alias does not automatically imply outbound permission.

This allows:

```text
billing@example.com → finance inbox
```

without automatically allowing an authenticated user to send as `billing@example.com`.

## Submission credentials

```bash
pigeon auth create <name>
pigeon auth info <name>
pigeon auth revoke <name>
pigeon auth rotate <name>
pigeon auth list
```

Example:

```bash
pigeon auth create macbook-mail
```

Output:

```text
Credential created.

Username: pg_7N...
Password: ********

The password is shown once.
Store it securely.
```

Then grant identities:

```bash
pigeon auth allow macbook-mail hello@example.com
pigeon auth allow macbook-mail founder@example.com
```

Or domain-wide permission:

```bash
pigeon auth allow-domain macbook-mail example.com
```

Domain-wide permission should be opt-in and clearly highlighted.

## Outbound mode

```bash
pigeon domain outbound example.com enable
pigeon domain outbound example.com disable

pigeon domain delivery example.com direct
pigeon domain delivery example.com relay <relay-name>
```

## Relay configuration

```bash
pigeon relay add <name>
pigeon relay info <name>
pigeon relay remove <name>
pigeon relay test <name>
```

Secrets should be requested interactively or read from stdin, never encouraged as command-line arguments.

## Route testing

Inbound:

```bash
pigeon route test hello@example.com
```

Outbound:

```bash
pigeon route test-outbound \
  --auth macbook-mail \
  --from hello@example.com \
  --to recipient@example.net
```

No message is sent.

## Queue

```bash
pigeon queue list
pigeon queue info <id>
pigeon queue retry <id>
pigeon queue retry-domain <domain>
pigeon queue remove <id>
pigeon queue freeze <id>
pigeon queue unfreeze <id>
```

Destructive queue removal should require confirmation unless `--yes` is given.

## DNS

```bash
pigeon dns show example.com
pigeon dns check example.com
pigeon dns show-spf example.com
pigeon dns show-dkim example.com
pigeon dns show-dmarc example.com
```

`dns show` prints the exact desired records without performing changes.

Pigeon does not require DNS-provider API credentials.

## Exit codes

Suggested stable contract:

```text
0   success / healthy
1   command or configuration error
2   DNS validation failure
3   runtime/system failure
4   database failure
5   queue/delivery failure
6   authentication/authorization failure
64  CLI usage error
```

## Output modes

Human-readable output is default.

Automation-friendly modes:

```bash
--json
--quiet
```

`--quiet` should emit nothing on success and rely on the process exit code.
