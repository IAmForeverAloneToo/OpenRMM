-- Phase 6.4: server updates from the dashboard. One settings row (daily
-- check on by default, the last check and the newest signed release found)
-- and the history of update requests with the updater's outcome.
CREATE TABLE server_update_settings(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    check_enabled INTEGER NOT NULL DEFAULT 1 CHECK (check_enabled IN (0, 1)),
    checked_at INTEGER,
    check_error TEXT NOT NULL DEFAULT '' CHECK (length(check_error) <= 300),
    available_json TEXT NOT NULL DEFAULT '' CHECK (length(available_json) <= 65536)
);
INSERT INTO server_update_settings(id) VALUES (1);

CREATE TABLE server_updates(
    id TEXT PRIMARY KEY CHECK (length(id) = 32),
    version TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    from_version TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('requested', 'accepted', 'pulling', 'backing_up', 'starting', 'succeeded', 'rolled_back', 'failed')),
    detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 300),
    backup TEXT NOT NULL DEFAULT '' CHECK (length(backup) <= 100),
    finished_at INTEGER
);
CREATE INDEX server_updates_requested ON server_updates(requested_at DESC);
