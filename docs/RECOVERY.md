# Recovery

What to do after something has already gone wrong. Ordered by what is at stake:
the mail that has not arrived yet, then the mail that was in flight, then the
keys.

Nothing here is theoretical about the queue's guarantees — a `250` means the
rows committed, and everything below is about getting back to a state where
those rows can be acted on.

---

## The disk filled up

Pigeon stops accepting below 256 MB free, with a `452`, so senders keep their
mail and retry. Nothing is lost while this is happening.

```bash
pigeon health                      # free space, queue depth
du -sh /var/lib/pigeon/spool
```

The spool holds one file per accepted message until every recipient is terminal.
If it is large, something is not draining — find it with `pigeon queue list`
before deleting anything.

**Do not delete spool files by hand.** A file whose row still exists becomes a
message that can never be delivered and never be reported on. If a destination
is hopeless, freeze it and let the horizon expire it:

```bash
pigeon queue freeze --domain hopeless.example
```

The horizon still runs while frozen, so those messages expire and their senders
are told — which is the outcome that does not swallow mail silently.

---

## The database is damaged

```bash
systemctl stop pigeond
pigeon verify /var/lib/pigeon/pigeon.db
```

`verify` distinguishes the two failures that look alike:

- **Integrity is not `ok`** — a page is corrupt. Restore; do not repair. A
  partially readable mail queue delivers some messages twice and loses others,
  and neither is visible until somebody asks where their mail went.
- **The schema is newer than this build supports** — this is a downgrade, not
  damage. Install the newer binary.

To restore:

```bash
systemctl stop pigeond
mv /var/lib/pigeon/pigeon.db /var/lib/pigeon/pigeon.db.damaged
cp /var/backups/pigeon-2026-09-01.db /var/lib/pigeon/pigeon.db
chown pigeon:pigeon /var/lib/pigeon/pigeon.db
sudo -u pigeon pigeon verify /var/lib/pigeon/pigeon.db
systemctl start pigeond
```

**Keep the damaged file.** It is the only copy of anything accepted since the
backup, and a later `sqlite3 .recover` on it may yield rows worth reading even
if it will not open.

### What a restore costs

Mail accepted **after** the backup was taken has rows in the damaged file and
not in the restored one. Its spool files are still on disk, unreferenced, and
the orphan sweep will remove them — they are not deliverable, because nothing
records who they were for.

Those senders were told `250`. They will not retry. That mail is lost, and the
window is exactly "since the last backup", which is the argument for taking one
daily rather than weekly.

---

## The spool is gone but the database is not

Every message shows as queued, and each attempt fails to read its body.

Pigeon records that as a **local** failure rather than a remote rejection —
telling a sender their recipient refused a message is false and unactionable
when the fault is here. Those deliveries will retry until the horizon and then
expire, generating reports to their senders.

If you know the bodies are unrecoverable, that is the correct outcome: let them
expire, and the senders find out. Freezing them instead only delays the same
result.

---

## The DKIM keys are gone

This is the one loss no backup of the database covers, because the private keys
are not in it.

Mail keeps flowing. It arrives unsigned or signed with a key whose record no
longer matches, which means DMARC failures at every receiver that checks — so it
lands in spam, gradually, without an error anywhere.

```bash
pigeon domains check     # reports "publishes a different key" per domain
```

The recovery is a new key per domain and a new DNS record for each. There is no
shortcut:

```bash
pigeon domain remove example.com --yes    # keeps the aliases? No — see below
```

**Do not do that.** Removing a domain deletes its routing. Instead, generate a
new key by adding the domain fresh on a scratch database to see the record
format, or restore the keys directory from a backup you took separately.

This is why `pigeon backup` prints a line about the keys directory every time it
runs. Copy it, and keep it somewhere the database backup is not.

---

## Both nodes disagree

```bash
pigeon config checksum     # on each
```

Different checksums mean different routing, which shows up to senders as
intermittent rejection — one MX accepts an address the other refuses.

```bash
# on the node you trust
pigeon config export /tmp/routing.csv

# on the other
pigeon import csv /tmp/routing.csv --replace
pigeon config checksum      # now identical
```

`--replace` removes aliases and the catch-all on the imported domains before
applying, which is what makes the two nodes converge rather than accumulate.
Check the plan it prints before confirming: it is the one command here that can
delete routing.

---

## The daemon will not start

Every startup failure is local, unambiguous and printed on stderr. Running
half-configured is worse than not running, so it refuses rather than degrading.

| Message | Cause |
|---|---|
| `PIGEON_CONFIG is unset` | no configuration file named |
| `… is 0755; it must be 0700` | a directory holding secrets is too permissive |
| `DKIM key for … cannot be read` | key file missing or unreadable by the daemon's user |
| `alerts.identity is … on a domain this host carries` | an alert about that domain could not be sent |
| `cannot bind 0.0.0.0:25` | another MTA is running, or no privilege |
| `the database was written by a newer build` | a downgrade |
| `running as root with no user configured` | set `user`, or use the systemd unit |

---

## Starting again from nothing

If the host is gone and you have the database and keys backups:

1. Install as in [DEPLOY.md](DEPLOY.md), through step 2.
2. Restore `pigeon.db` and the `keys/` directory. Restore `srs.key` too, or
   bounces for mail already in flight will not verify.
3. `pigeon verify`, then start.
4. `pigeon domains check` — the MX records still point at the old address if the
   address changed, and that is a `FATAL` finding with the record to publish.

If you have the keys but not the database, you keep your DKIM identity and lose
the routing: re-add domains and re-import aliases. If you have the database but
not the keys, the reverse — routing intact, every domain needing a new key and a
new record.
