-- "No report was required" and "a report was owed and can never be sent" are
-- different facts, and `notification = 'none'` was saying both.
--
-- The first is ordinary: a delivery that succeeded, or one whose message had a
-- null return path because it was itself a bounce. The second is a fault — a
-- return path that will not verify, a key deleted before its retirement
-- barrier — where somebody was owed an explanation and will never get one.
--
-- Collapsing them means "how many senders never heard back?" has no answer, and
-- the rows that should be investigated are indistinguishable from the ones that
-- are working exactly as intended.

CREATE TABLE delivery_new (
    id               INTEGER PRIMARY KEY,
    message_id       INTEGER NOT NULL REFERENCES message(id) ON DELETE CASCADE,
    destination      TEXT NOT NULL,

    state            TEXT NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued','delivering','deferred','delivered','failed','expired')),

    notification     TEXT NOT NULL DEFAULT 'none'
        CHECK (notification IN ('none','owed','enqueued','abandoned')),
    notified_by      INTEGER REFERENCES message(id) ON DELETE SET NULL,

    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  INTEGER,

    claimed_by       TEXT,
    claim_token      TEXT,
    lease_expires_at INTEGER,

    last_code        INTEGER,
    last_response    TEXT,
    terminal_at      INTEGER,

    UNIQUE (message_id, destination),

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
    -- Anything other than `none` is about a failure, so it can only sit on one.
    CHECK (notification = 'none' OR state IN ('failed','expired')),
    CHECK ((notification = 'enqueued') = (notified_by IS NOT NULL))
) STRICT;

INSERT INTO delivery_new (id, message_id, destination, state, notification, notified_by,
                          attempts, next_attempt_at, claimed_by, claim_token,
                          lease_expires_at, last_code, last_response, terminal_at)
SELECT id, message_id, destination, state, notification, notified_by,
       attempts, next_attempt_at, claimed_by, claim_token,
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

-- Reports that will never be sent, for the operator query that asks how many
-- senders were left without an answer.
CREATE INDEX delivery_abandoned ON delivery(terminal_at)
    WHERE notification = 'abandoned';
