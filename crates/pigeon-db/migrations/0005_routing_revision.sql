-- A counter that moves when *routing* changes, and not when anything else does.
--
-- `data_version` was the previous doorbell, and it is accidentally total: it
-- moves for every commit to the database. That was free while the database held
-- only configuration. It stops being free now that the queue shares the file —
-- a busy relay commits delivery rows continuously, and a detector watching
-- `data_version` would load and hash the routing tables once a second forever
-- to conclude each time that nothing routing-related had changed
-- (`M1-RELOAD.md` §2).
--
-- The triggers below are deliberately on the routing tables *only*. `message`,
-- `delivery`, `original_recipient`, `recipient_delivery` and `delivery_event`
-- have none, which is the whole point: queue commits must not advance the
-- routing revision.

CREATE TABLE routing_revision (
    -- One row, enforced. A counter with two rows is two counters.
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;

INSERT INTO routing_revision(id, revision) VALUES (1, 1);

-- Triggers rather than application code, so no writer can forget. A `pigeon`
-- command, a repair by hand in `sqlite3`, a restore that replays statements —
-- all of them move the counter, because all of them change what the daemon
-- would serve.
CREATE TRIGGER routing_revision_domain_insert AFTER INSERT ON domain
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_domain_update AFTER UPDATE ON domain
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_domain_delete AFTER DELETE ON domain
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;

CREATE TRIGGER routing_revision_alias_insert AFTER INSERT ON alias
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_alias_update AFTER UPDATE ON alias
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_alias_delete AFTER DELETE ON alias
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;

CREATE TRIGGER routing_revision_alias_destination_insert AFTER INSERT ON alias_destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_alias_destination_update AFTER UPDATE ON alias_destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_alias_destination_delete AFTER DELETE ON alias_destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;

-- Destinations are what aliases resolve *to*, so editing one changes where mail
-- goes without touching a routing row that mentions it.
CREATE TRIGGER routing_revision_destination_insert AFTER INSERT ON destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_destination_update AFTER UPDATE ON destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_destination_delete AFTER DELETE ON destination
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;

-- Keys are part of the published runtime: adding or rotating one changes what
-- a domain can sign with, and the snapshot and the keys are installed together.
CREATE TRIGGER routing_revision_dkim_key_insert AFTER INSERT ON dkim_key
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_dkim_key_update AFTER UPDATE ON dkim_key
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
CREATE TRIGGER routing_revision_dkim_key_delete AFTER DELETE ON dkim_key
BEGIN UPDATE routing_revision SET revision = revision + 1 WHERE id = 1; END;
