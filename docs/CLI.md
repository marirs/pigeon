# CLI Reference

The public command is `pigeon`. The service unit is `pigeond`, but you should not need to touch it directly.

## Shape

Every command reads the same way:

```text
pigeon <noun> <verb> [target] [arguments]
```

Nouns are stable and few. Verbs repeat across nouns, so learning one noun teaches you the rest:

```text
list     show everything of this kind
add      create one
remove   delete one
show     details of one
check    validate one against DNS
test     try it without committing anything
```

Singular acts on one thing, plural on all of them:

```bash
pigeon domain check example.com   # one
pigeon domains check              # all
```

## Help at every level

Every level of the tree is self-documenting, and a bare noun prints its own help rather than an error.

```bash
pigeon                    # overview, most common commands
pigeon domain             # everything you can do to a domain
pigeon domain add --help  # this one command, in detail
```

`pigeon`:

```text
Pigeon — self-hosted email forwarding.

USAGE
  pigeon <command> [options]

SETUP
  domain      add and configure a domain
  alias       forward an address to a mailbox
  catchall    forward everything else
  destination where your mail lands, across all domains
  dns         show the records you need to publish

RUNNING
  run         start the daemon
  status      show what the daemon is doing
  check       validate the whole installation

INSPECT
  route       trace where an address would go
  queue       inspect undelivered mail
  domains     act on every domain at once

SENDING
  sender      addresses a domain may send as
  auth        submission credentials
  relay       upstream smarthost configuration

OTHER
  alerts      operator notifications
  import      bulk import from another provider
  send        send a diagnostic message

  pigeon <command> --help   for detail on any of these

Getting started:

  pigeon domain add example.com
```

`pigeon domain`:

```text
Add and configure a domain.

USAGE
  pigeon domain <verb> <domain> [arguments]

VERBS
  add          add a domain and generate its DKIM key
  remove       delete a domain and everything under it
  show         status, records, aliases, queue summary
  check        validate DNS and update the domain's state
  forward      set where this domain's mail goes by default
               (moves inherited aliases; previews and confirms)
  enable       allow this domain to receive mail
  disable      stop this domain receiving mail
  notify       set where alerts for this domain are sent
  outbound     allow or block sending as this domain
  delivery     choose direct or relay delivery

EXAMPLES
  pigeon domain add example.com --to me@example.net
  pigeon domain check example.com
  pigeon domain show example.com
  pigeon domain forward example.com me@example.net
  pigeon domain notify example.com ops@example.net
  pigeon domain outbound example.com on

SEE ALSO
  pigeon domains        act on every domain
  pigeon alias          forwarding rules for a domain
  pigeon catchall       forward everything unmatched
```

`pigeon domain add --help`:

```text
Add a domain and generate its DKIM key.

USAGE
  pigeon domain add <domain> [options]

Creates the domain, generates an RSA-2048 DKIM key, and prints the DNS
records you need to publish. The domain starts in PENDING_DNS and cannot
receive mail until every record is live and validated.

The private key is written to the keys directory and never leaves this
host. It cannot be regenerated without republishing DNS, so include it in
your backups.

OPTIONS
  --to <address>         where this domain's mail goes by default;
                         aliases inherit it unless given their own
  --catchall             also forward everything unmatched
  --notify <address>     send alerts for this domain here
  --json                 machine-readable output

EXAMPLES
  pigeon domain add example.com
  pigeon domain add example.com --to me@example.net
  pigeon domain add example.com --to me@example.net --catchall

NEXT
  Publish the records, then run:
    pigeon domain check example.com
```

Three rules hold everywhere:

- **Every help page ends with examples.** A syntax summary alone leaves you guessing at argument order.
- **Every command that has an obvious next step prints it.** Adding a domain tells you to check it; a failing check tells you what to publish.
- **Every error names the fix**, not just the fault.

```text
$ pigeon alias add exmaple.com hello me@example.net

Error: no such domain 'exmaple.com'

  Did you mean 'example.com'?

  See configured domains with:
    pigeon domains list
```

---

## Running

```bash
pigeon run              # start in the foreground
pigeon status           # what the daemon is doing
pigeon check            # validate system and all domains
```

`pigeon check` is the whole-installation test: local configuration first, then every domain. Exit code `0` means safe to serve mail.

Under systemd:

```bash
systemctl enable --now pigeond
```

## Domains

```bash
pigeon domain add <domain>
pigeon domain remove <domain>
pigeon domain show <domain>
pigeon domain check <domain>
pigeon domain forward <domain> <address>
pigeon domain enable <domain>
pigeon domain disable <domain>
pigeon domain notify <domain> <address>
pigeon domain outbound <domain> on|off
pigeon domain delivery <domain> direct|relay <name>

pigeon domains list
pigeon domains check
```

`domain show` reports lifecycle state, inbound and outbound enablement, delivery mode, expected against observed MX, SPF/DKIM/DMARC state, aliases, catch-all, sender identities, queue summary and last check time.

A domain reaches `ACTIVE` only by passing every required check. There is no override.

### Removing a domain

This is the most destructive command in Pigeon, and the only one that requires you to type the name back:

```text
$ pigeon domain remove example.com

This permanently deletes:

  14 aliases
  catch-all → me@example.net
  3 sender identities
  2 queued messages, undelivered

  DKIM private key   pigeon._domainkey.example.com

The DKIM key cannot be regenerated. Re-adding example.com later
creates a new key and requires publishing a new DNS record.

Queued messages are deleted, not delivered. Pigeon keeps no copy.

Type the domain name to confirm: _
```

`--yes` skips it, and exists for automation rather than for saving four seconds.

The prompt is heavier than elsewhere because two of those lines are irreversible in ways that are not obvious at the moment of typing: the DKIM key is the one piece of state no backup of the database will restore, and queued messages have already been accepted, so deleting them loses mail that a sender believes was delivered.

## Where mail goes

A domain has one default destination. Aliases inherit it, so the common case — many addresses on many domains all landing in one mailbox — needs the destination typed exactly once.

```bash
pigeon domain add example.com --to me@example.net
pigeon domain forward example.com me@example.net    # change it later
```

Aliases inherit that default. Passing `--to` on an alias overrides it for that alias alone:

```bash
pigeon alias add example.com hello,hi,support        # → me@example.net
pigeon alias add example.com abuse --to abuse@example.org
```

Because aliases inherit it, changing the default moves all of them at once. `domain forward` therefore shows what it will move and confirms first:

```text
$ pigeon domain forward example.com new@example.net

Changing the default destination for example.com:

  me@example.net  →  new@example.net

6 aliases inherit the default and will move:

  hello, hi, support, sales, orders, admin

2 aliases have their own destination and will not change:

  billing   → finance@example.net
  abuse     → abuse@example.org

Catch-all inherits the default and will move.

Continue? [y/N]
```

Setting a default on a domain that has none yet changes nothing retroactively, so it applies without prompting. `--dry-run` shows the preview alone; `--yes` skips the prompt in scripts.

This is the same operation as `pigeon destination replace` reached from the other side — one changes every alias on one domain, the other changes one address across every domain — so they share their preview, `--dry-run` and `--yes` behaviour.

## Aliases

```bash
pigeon alias list <domain>
pigeon alias add <domain> <names> [--to <destination>...]
pigeon alias remove <domain> <names>
pigeon alias remove <domain> --all
```

Names are comma-separated, so several aliases are one command:

```bash
pigeon alias add example.com hello
pigeon alias add example.com hello,hi,support
```

```text
Added to example.com:

  hello@example.com    → me@example.net
  hi@example.com       → me@example.net
  support@example.com  → me@example.net

3 aliases using the domain default.
```

Override the destination for one alias, or fan it out to several:

```bash
pigeon alias add example.com billing --to finance@example.net
pigeon alias add example.com security --to a@example.net,b@example.net
```

Positional arguments are always alias names and `--to` is always destinations, so the two can never be confused for each other.

Adding an alias to a domain with no default and no `--to` is an error that tells you both ways out:

```text
Error: example.com has no default destination

  Set one:
    pigeon domain forward example.com me@example.net

  Or give this alias its own:
    pigeon alias add example.com hello --to me@example.net
```

### Wildcards

Quote the pattern so your shell does not expand it:

```bash
pigeon alias add example.com 'shop-*'
```

Patterns are globs, not regular expressions. Local parts arrive from the network, and a regex engine evaluating untrusted input invites catastrophic backtracking. When several wildcards match, the longest pattern wins.

### Removing

```bash
pigeon alias remove example.com hello
pigeon alias remove example.com hello,hi,support
pigeon alias remove example.com --all
```

Removing everything is `--all`, deliberately a flag rather than `*` or the word `all`.

Both alternatives are ambiguous in a way that loses data. `*` is already valid as a wildcard alias, so `alias remove example.com '*'` could plausibly mean *delete the catch-all wildcard* or *delete all forty aliases* — and unquoted, the shell may expand it against your working directory into something else entirely. `all` is a real address people use, so `all@example.com` is an alias somebody has.

`--all` cannot be mistaken for a name. It confirms before deleting unless given `--yes`.

### Rejects

An address that must never be accepted is an alias with no destination:

```bash
pigeon alias add example.com postmaster-old --reject
pigeon alias remove example.com postmaster-old
```

It appears in `alias list` marked `REJECT` and takes precedence over everything else.

## Catch-all

```bash
pigeon catchall add <domain> [--to <destination>]
pigeon catchall remove <domain>
pigeon catchall show <domain>
```

```bash
pigeon catchall add example.com                        # domain default
pigeon catchall add example.com --to me@example.net    # or its own
```

Anything no alias claims is forwarded. Explicit aliases always win.

Catch-all is never enabled implicitly. It exists only after `catchall add`.

### Catch-all and aliases together

They are not alternatives. Catch-all handles the long tail; aliases handle the addresses that need to go somewhere else, be split between people, or be refused outright.

If every alias on a domain points at the same place as the catch-all, then yes — the aliases are doing nothing, and catch-all alone is the simpler configuration. Pigeon says so rather than leaving you to notice:

```text
$ pigeon alias add example.com sales

Added:

  sales@example.com → me@example.net

Note: catch-all already forwards unmatched addresses to me@example.net,
so this alias does not change where mail goes.

  Useful anyway if you plan to point it elsewhere later, or want it
  listed explicitly. Otherwise it can be removed.
```

Adding a catch-all reports the same thing from the other direction:

```text
$ pigeon catchall add example.com

Catch-all enabled: → me@example.net

6 of 8 existing aliases now forward to the same destination and no
longer affect routing. Review with:

  pigeon alias list example.com
```

`alias list` marks them, so a domain's real routing is visible at a glance:

```text
ALIAS                  DESTINATION              
hello                  me@example.net           (same as catch-all)
hi                     me@example.net           (same as catch-all)
billing                finance@example.net      
security               a@example.net, b@example.net
postmaster-old         —                        REJECT

catch-all              me@example.net
```

Nothing is refused or removed automatically. A redundant alias is a fact about your configuration, not an error, and it becomes meaningful the moment the catch-all destination changes.

### The cost of catch-all

With catch-all enabled, every address on the domain is accepted at `RCPT TO`.

Recipient rejection stops applying, so dictionary attacks receive `250` instead of `550`, spam volume rises, and any accepted message that later proves undeliverable must be bounced — which is the backscatter path recipient rejection exists to avoid.

Catch-all is the right choice for a domain where you genuinely want every address to work. It is a poor default for a domain with six real addresses on it.

## Destinations

Aliases are managed per domain. Destinations are the other axis: one mailbox usually receives from many aliases across many domains, and when that mailbox changes you need to move all of them at once.

```bash
pigeon destination list
pigeon destination list --domain example.com
pigeon destination replace <old> <new>
pigeon destination replace <old> <new> --domain example.com
```

`destination list` answers "where does my mail actually go?", which stops being obvious somewhere around the fifth domain:

```text
DESTINATION            ALIASES   DOMAINS   DEFAULT FOR
me@example.net             187        38            38
finance@example.net          4         2             -
ops@example.net              2         2             -
old@previous.net            11         3             1
```

That last row is the kind of thing this command exists to surface — a mailbox you thought you had finished migrating.

`destination replace` repoints every use of an address: aliases, catch-all destinations, and any domain default pointing at it. It spans all domains unless `--domain` narrows it, because migrating one mailbox across forty domains is the entire point.

It always previews and confirms:

```text
$ pigeon destination replace old@previous.net me@example.net

This will repoint 11 aliases across 3 domains:

  example.com     hello, support, billing            (3)
  example.net     hello, hi, sales, orders           (4)
  project.dev     hello, admin, security, abuse      (4)

  example.com     default destination

Continue? [y/N]
```

Use `--dry-run` to see the preview without the prompt, or `--yes` to skip it in a script.

## Loops

Pigeon refuses aliases that forward into themselves, at the point you add them rather than the point mail arrives:

```text
$ pigeon alias add example.com abuse --to abuse@example.com

Error: this alias would forward to itself

  abuse@example.com → abuse@example.com

  example.com is managed by this Pigeon, so the destination resolves
  back to the alias being created.

  Forward to a mailbox outside Pigeon, or to another managed domain
  that does not route back here.
```

The same check covers indirect cycles — `a@one.com → b@two.com → a@one.com` — by walking the destination chain through every managed domain before committing.

Catching this at configuration time matters because the runtime symptom is nothing like the cause: messages multiply through the queue, delivery counters climb, and the offending alias looks fine in isolation. Loop detection still runs at delivery for chains that leave and re-enter through systems Pigeon cannot see, but that is a backstop, not the first line.

Precedence, highest first:

```text
exact alias  →  wildcard (most literal characters)  →  catch-all  →  reject unknown
```

The most specific matching rule wins, and whether that rule forwards or rejects
is then its own business. So a reject rule refuses everything that no *more
specific* rule claims — `hell*` set to reject does not disable an explicit
`hello` alias. An address that must never be accepted under any circumstances is
written as an exact reject, which nothing outranks.

Plus-addressing is on by default per domain. `hello+github@example.com` matches the `hello` alias and the tag survives into the forwarded message.

```bash
pigeon domain plus-addressing example.com off
```

## Route testing

Trace an address without sending anything.

```bash
pigeon route inbound hello@example.com
pigeon route outbound --as macbook-mail --from hello@example.com --to you@example.net
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

```text
REJECT

Reason:
  alias not found
  catch-all disabled
```

## Sending

Sending is separate from forwarding. An inbound alias grants no authority to send.

```bash
pigeon sender list <domain>
pigeon sender add <domain> <local-part>
pigeon sender remove <domain> <local-part>
```

Credentials are application credentials, not mailbox passwords.

```bash
pigeon auth create <name>
pigeon auth list
pigeon auth show <name>
pigeon auth allow <name> <address>
pigeon auth revoke <name>
pigeon auth rotate <name>
```

A wildcard grants a whole domain, reusing the pattern syntax from aliases:

```bash
pigeon auth allow macbook-mail hello@example.com
pigeon auth allow macbook-mail '*@example.com'
```

Domain-wide grants are called out clearly when made. Secrets are shown once and never printed again.

## Relays

```bash
pigeon relay list
pigeon relay add <name>
pigeon relay remove <name>
pigeon relay test <name>
```

Secrets are prompted for or read from stdin, never taken as command-line arguments where they would land in your shell history.

## Queue

```bash
pigeon queue list
pigeon queue show <id>
pigeon queue retry <id>
pigeon queue retry --domain <domain>
pigeon queue remove <id>
pigeon queue freeze <id>
pigeon queue unfreeze <id>
```

Removal is permanent — Pigeon retains no copy — so it confirms unless given `--yes`.

## DNS

```bash
pigeon dns show <domain>
pigeon dns show <domain> --record mx|spf|dkim|dmarc
pigeon dns check <domain>
```

`dns show` prints the exact records to publish and changes nothing. Pigeon never needs credentials for your DNS provider.

## Alerts

Pigeon emails you when a domain is gated or recovers. See [`ALERTING.md`](ALERTING.md).

```bash
pigeon alerts show
pigeon alerts test
pigeon alerts test --domain example.com
```

`alerts test` sends a real message through the out-of-band alert path and reports each step, exiting non-zero on failure so cron or an external monitor can drive it. Run it after setup and periodically: a broken alert path produces silence, which is indistinguishable from health.

## Import

```bash
pigeon import <provider> --api-key <key> --dry-run
pigeon import csv aliases.csv
```

`--dry-run` prints the diff without writing. Run it first.

Imported domains land in `PENDING_DNS` regardless of their state elsewhere, because their DNS still points at the previous host. Keep the previous provider as a lower-priority MX during cutover:

```text
example.com  MX 10 mx1.yourserver.net
             MX 20 mx.previous-provider.net
```

## Diagnostic send

```bash
pigeon send test --from hello@example.com --to you@example.net
```

Goes through the real submission path — sender authorisation, DKIM signing, configured delivery mode — so it exercises what ordinary mail will do. Unlike `alerts test`, which is out of band by design.

Both are configuration diagnostics, not general-purpose send commands.

---

## Global options

Accepted by every command:

```text
-h, --help       help for this command
    --json       machine-readable output (read commands)
    --quiet      print nothing on success; rely on the exit code
    --yes        skip confirmation on destructive or bulk commands
    --dry-run    show what would change, then stop
    --config     path to pigeon.toml
```

`--json` output is a stable contract. It is the seam anything built on top of Pigeon consumes, and a process boundary keeps that integration free of any coupling to the database schema.

## Exit codes

```text
0   success / healthy
1   command or configuration error
2   DNS validation failure
3   runtime or system failure
4   database failure
5   queue or delivery failure
6   authentication or authorisation failure
64  CLI usage error
```

Stable across releases, so scripts can branch on them.

## Where commands run

Read commands open SQLite directly. Mutating commands go through the daemon's Unix socket while it is running, so there is only ever one writer and changes are validated against live state before they commit. Offline mutation is permitted only when the daemon is stopped.
