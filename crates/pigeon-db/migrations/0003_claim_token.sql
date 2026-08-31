-- A claim needs a token, not just an owner.
--
-- `claimed_by` says *which worker* holds a delivery. That is not enough to
-- decide whether an update may land: a worker whose lease expired, whose row
-- was reclaimed by a replacement, and which then finishes its own attempt would
-- pass a `claimed_by = me` check if it were ever handed the row again — and
-- worse, an identical worker identity after a restart makes the check
-- meaningless.
--
-- What every completion has to be conditional on is *this attempt still owning
-- the row*, which needs a value unique per claim. The token is generated at
-- claim time and checked by every update that follows, so a worker that lost
-- the lease cannot overwrite the result its replacement produced.
--
-- The table is recreated rather than altered because the constraint is
-- table-level: the token, the owner and the state are one fact, and SQLite
-- cannot add a table CHECK to an existing table.

CREATE TABLE delivery_new (
    id               INTEGER PRIMARY KEY,
    message_id       INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    destination      TEXT NOT NULL,

    state            TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','delivering','deferred','delivered','failed','expired')),

    notification     TEXT NOT NULL DEFAULT 'none'
        CHECK (notification IN ('none','owed','enqueued')),
    notified_by      INTEGER REFERENCES message(id) ON DELETE SET NULL,

    -- How many times this delivery has been *claimed*. Crash accounting, not
    -- evidence about the remote: a worker killed before it connected still
    -- increments this, so a run of local crashes must never be what decides a
    -- message is undeliverable. Expiry is governed by age (M3-DESIGN §7).
    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),

    next_attempt_at  INTEGER,

    claimed_by       TEXT,
    -- Unique per claim. Every completion, deferral and failure is conditional
    -- on it, which is what fences a worker whose lease has expired.
    claim_token      TEXT,
    lease_expires_at INTEGER,

    last_code        INTEGER,
    last_response    TEXT,
    terminal_at      INTEGER,

    UNIQUE (message_id, destination),

    -- All three columns of a claim, or none of them. Half a claim is a row
    -- nothing reclaims and nothing completes.
    CHECK (
        (claimed_by IS NULL) = (lease_expires_at IS NULL)
        AND (claimed_by IS NULL) = (claim_token IS NULL)
    ),
    CHECK (
        (state = 'delivering')
        = (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL AND claim_token IS NOT NULL)
    ),
    CHECK ((state IN ('delivered','failed','expired')) = (terminal_at IS NOT NULL)),
    CHECK ((state IN ('queued','deferred')) = (next_attempt_at IS NOT NULL)),
    CHECK (notification = 'none' OR state IN ('failed','expired')),
    CHECK ((notification = 'enqueued') = (notified_by IS NOT NULL))
) STRICT;

INSERT INTO delivery_new (id, message_id, destination, state, notification, notified_by,
                          attempts, next_attempt_at, claimed_by, claim_token,
                          lease_expires_at, last_code, last_response, terminal_at)
SELECT id, message_id, destination, state, notification, notified_by,
       attempts, next_attempt_at, claimed_by,
       -- Any row mid-delivery at migration time gets a token, so the new
       -- constraint holds and its lease still expires normally.
       CASE WHEN claimed_by IS NULL THEN NULL ELSE 'migrated-' || id END,
       lease_expires_at, last_code, last_response, terminal_at
  FROM delivery;

DROP TABLE delivery;
ALTER TABLE delivery_new RENAME TO delivery;

CREATE INDEX delivery_due ON delivery(next_attempt_at)
    WHERE state IN ('queued','deferred');
CREATE INDEX delivery_owed ON delivery(message_id)
    WHERE notification = 'owed';
CREATE INDEX delivery_leases ON delivery(lease_expires_at)
    WHERE state = 'delivering';
CREATE INDEX delivery_by_message ON delivery(message_id);
