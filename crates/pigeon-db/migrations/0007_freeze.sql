-- Holding mail back without losing it.
--
-- A frozen delivery is not claimed and not retried, and its horizon still runs:
-- freezing is a decision to stop *trying*, not a decision to stop the clock. An
-- operator who freezes a destination that is misbehaving and forgets about it
-- gets the same expiry and the same report as one who did nothing, which is the
-- outcome that does not silently swallow mail.
--
-- Nullable timestamp rather than a boolean, because "since when" is the first
-- question anyone asks about a held queue.
ALTER TABLE delivery ADD COLUMN frozen_at INTEGER;

-- Due work skips frozen rows. The index is partial for the same reason the
-- others are: after a day the table is mostly terminal rows, and a frozen row
-- is rarer still.
CREATE INDEX delivery_frozen ON delivery(frozen_at) WHERE frozen_at IS NOT NULL;
