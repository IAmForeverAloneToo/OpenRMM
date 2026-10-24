CREATE TABLE device_cpu (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    capability_version INTEGER NOT NULL,
    last_status TEXT NOT NULL CHECK (last_status IN ('ok','failed','disabled','unsupported')),
    reported_at INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL DEFAULT '',
    snapshot_at INTEGER
);
