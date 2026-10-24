CREATE TABLE device_event_logs (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    capability_version INTEGER NOT NULL,
    last_status TEXT NOT NULL CHECK (last_status IN ('ok','failed','disabled','unsupported')),
    reported_at INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL DEFAULT '',
    snapshot_at INTEGER
);

CREATE TABLE event_log_queries (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 device_id TEXT NOT NULL REFERENCES devices(id),
 actor TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 dispatched_at INTEGER,
 finished_at INTEGER,
 status TEXT NOT NULL CHECK(status IN ('queued','dispatched','succeeded','failed','expired','unknown','cancelled')),
 filter_json TEXT NOT NULL,
 result_json TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX event_log_one_active ON event_log_queries(device_id) WHERE status IN ('queued','dispatched');
CREATE INDEX event_log_recent ON event_log_queries(device_id,created_at DESC);
