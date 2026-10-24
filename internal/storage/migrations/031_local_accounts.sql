-- Phase 1b: local accounts and the members of the Administrators and Remote
-- Desktop Users groups. The newest report per device; a failed report keeps
-- the last good snapshot.
CREATE TABLE device_local_accounts (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER
);
