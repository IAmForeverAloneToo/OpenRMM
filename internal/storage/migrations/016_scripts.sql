CREATE TABLE script_versions (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 script_id TEXT NOT NULL CHECK(length(script_id)=32),
 version INTEGER NOT NULL,
 sha256 TEXT NOT NULL CHECK(length(sha256)=64),
 definition_json TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 actor TEXT NOT NULL,
 UNIQUE(script_id,version)
);
CREATE INDEX script_versions_latest ON script_versions(script_id,version DESC);
CREATE TABLE device_script_support (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL,
 reported_at INTEGER NOT NULL,
 support_json TEXT NOT NULL DEFAULT ''
);
CREATE TABLE script_runs (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 device_id TEXT NOT NULL REFERENCES devices(id),
 version_id TEXT NOT NULL REFERENCES script_versions(id),
 arguments_json TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 dispatched_at INTEGER,
 finished_at INTEGER,
 cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN(0,1)),
 status TEXT NOT NULL CHECK(status IN('queued','dispatched','running','succeeded','failed','cancelled','expired','unknown')),
 result_json TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX script_runs_one_active ON script_runs(device_id) WHERE status IN('queued','dispatched','running');
CREATE INDEX script_runs_recent ON script_runs(device_id,created_at DESC,id);
