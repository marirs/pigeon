# Operating Pigeon

What to do when something is wrong, and what to set up before it is.

Everything here works against the database and the spool directly. There is no
control socket: adding one to answer "what is stuck?" would mean adding a
protocol, a permission model and a failure mode to a question SQLite already
answers — and a health command that needed the socket would report "unhealthy"
when the socket was the only broken thing.

---

## Is it working?

```
pigeon health
```

One screen and an exit code. Non-zero means one of two things, and only these
two, because a check that pages on volume is one people turn off:

- a domain is **gated** — its DNS no longer passes, so it has stopped accepting
  its own mail;
- mail has been **waiting more than a day**, which is a queue that is not
  draining rather than a queue that is busy.

`pigeon health --json` is the same information for a monitoring system.

For the deeper questions:

| Question | Command |
|---|---|
| Why is this domain gated? | `pigeon domain check example.com` |
| Are any domains about to be? | `pigeon domains check` |
| What is stuck? | `pigeon queue list` |
| What happened to *this* message? | `pigeon queue show <id>` |
| Do alerts actually reach me? | `pigeon alerts test` |

---

## The queue

```
pigeon queue list                      # what is waiting
pigeon queue show 1788264852-0bad-01   # everything recorded about one message
pigeon queue retry --domain slow.example
pigeon queue freeze --domain broken.example
pigeon queue thaw --domain broken.example
```

**Freezing stops Pigeon trying. It does not stop the clock.** A frozen delivery
still expires at the five-day horizon and its sender is still told. That is
deliberate: a freeze an operator sets and forgets would otherwise swallow mail
silently, and the whole queue is built so that nothing disappears without
somebody being told.

Retrying thaws as well — "retry this now" from the operator who froze it means
what it says — and neither command revives a terminal delivery. A delivered
message is not resent, and a failed one has already had its report generated;
reviving it would deliver a message whose sender was told it failed.

---

## Backups

```
pigeon backup /var/backups/pigeon-$(date +%F).db
pigeon verify /var/backups/pigeon-2026-09-02.db
```

`backup` uses SQLite's own backup API rather than copying the file: a `cp` taken
while the daemon is writing can be torn across a WAL checkpoint, and the result
is a file that opens and then fails on the one page that matters. The copy is
integrity-checked before the command returns, because a backup nobody has read
is a hope.

**The DKIM private keys are not in the database.** They are the only state no
backup of it restores: without them every domain needs a new key and a new DNS
record, published by hand, while mail is failing DMARC. Back up the keys
directory as well, and keep it somewhere the database backup is not.

To restore: stop the daemon, put the database back, put the keys back, run
`pigeon verify`, then start it. `verify` distinguishes the two failures that
look alike — a corrupt page is a disk problem, and a schema from a newer build
is a downgrade, which needs a different binary rather than a restore.

---

## Disk

Acceptance stops when the spool filesystem has less than 256 MB free: the
connection is refused with `452` and the sender keeps the message. Accepting
mail and then failing to write it is the same outage with a lost message on the
end of it.

`pigeon health` reports the free space. The spool holds one file per accepted
message until every recipient is terminal, so the working set is roughly
"messages in flight × their size", and the queue's five-day horizon bounds how
long a stuck destination can accumulate.

---

## Metrics

Off unless configured:

```toml
[metrics]
listen = "127.0.0.1:9187"
```

Prometheus text format at `/metrics`. **Bind it to loopback.** It is
unauthenticated and describes who sends mail here, what is failing and which
domains are gated — an operational map of the host. A scraper on the same
machine needs no authentication; anything else does, and Pigeon has none to
offer. The daemon logs a warning at startup if the address is not loopback.

`pigeon_up 0` means the daemon could not read its own database. Everything else
is read from the database per scrape rather than from in-process counters, which
would be a second copy that drifts on restart and disagrees with
`pigeon health`.

---

## Logs

Pigeon writes structured lines to stderr and rotates nothing itself. Under
systemd the journal handles that already, and a daemon that rotated its own logs
would be a second thing to configure and a second thing to get wrong.

- **journald**: nothing to do. `journalctl -u pigeond -f`.
- **A file**: point stderr at one in the unit
  (`StandardError=append:/var/log/pigeon.log`) and give logrotate a
  `copytruncate` stanza. Pigeon holds no log file handle it needs reopening, so
  `copytruncate` is safe and `postrotate` signalling is not required.

`RUST_LOG=debug` raises the level. It is verbose per message and belongs on a
host that is being debugged rather than on one that is working.

---

## Upgrades

```
systemctl stop pigeond      # drains: stops accepting, then finishes what is in flight
install -m0755 pigeond /usr/local/bin/pigeond
systemctl start pigeond     # migrates the database forwards, then serves
```

Shutdown is ordered and bounded: accepting and claiming stop first, then open
sessions and deliveries in flight get 20 seconds. Anything cut short is safe by
construction — a session with no `250` never had one and its sender retries, and
an abandoned delivery holds a token-fenced claim whose row returns to the queue
when the lease expires.

Migrations run forwards on start and take a backup first. **Downgrades are not
supported**: an older binary refuses a database written by a newer one rather
than guessing at a schema it does not know. Keep the pre-upgrade backup until
the new version has run for a while.

A rolling upgrade across two hosts is Milestone 8's subject; on one host the
window above is the whole story.

---

## When mail stops

In the order that finds it fastest:

1. `pigeon health` — gated domains and queue age.
2. `pigeon domains check` — what DNS says, and the exact records to publish.
3. `pigeon queue list` — whether anything is being attempted at all, and what
   the last destination said.
4. `journalctl -u pigeond -n 200` — refusals, blocklist decisions, TLS
   handshake failures.
5. `pigeon verify` — if the database itself is suspect.

The one failure this cannot show you is the alert channel: email about email
infrastructure shares a failure domain with the thing it monitors, and its
silence looks exactly like health. `pigeon alerts test` is the only way to know
it works.
