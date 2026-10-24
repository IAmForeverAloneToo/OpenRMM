-- Phase 1a: signed-in sessions. The newest report per device, and the sessions
-- the agent observed: one row per Windows session (session ID, user and logon
-- time) with when it was first and last seen and when it was gone. "Observed
-- by the agent", not a logon audit. Kept for 365 days, at most 2,000 rows per
-- device and 500,000 overall (owner decision, Phase 1).
CREATE TABLE device_sessions (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER
);
CREATE TABLE session_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 session_key TEXT NOT NULL,
 user_name TEXT NOT NULL,
 domain TEXT NOT NULL,
 session_json TEXT NOT NULL,
 first_seen_at INTEGER NOT NULL,
 last_seen_at INTEGER NOT NULL,
 ended_at INTEGER,
 UNIQUE(device_id, session_key)
);
CREATE INDEX session_history_device ON session_history(device_id, last_seen_at DESC, id DESC);
CREATE INDEX session_history_retention ON session_history(last_seen_at, id);
