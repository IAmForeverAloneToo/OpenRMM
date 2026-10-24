CREATE TABLE device_processes (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER
);
CREATE TABLE process_actions (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 device_id TEXT NOT NULL REFERENCES devices(id),
 pid INTEGER NOT NULL,
 start TEXT NOT NULL,
 name TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 dispatched_at INTEGER,
 finished_at INTEGER,
 status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','unknown','expired','cancelled')),
 outcome TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX process_actions_one_active ON process_actions(device_id) WHERE status IN ('queued','dispatched');
CREATE INDEX process_actions_recent ON process_actions(device_id,created_at DESC);
