CREATE TABLE device_file_support(
 device_id TEXT PRIMARY KEY REFERENCES devices(id),capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL,reported_at INTEGER NOT NULL,support_json TEXT NOT NULL
);
CREATE TABLE file_jobs(
 id TEXT PRIMARY KEY CHECK(length(id)=32),device_id TEXT NOT NULL REFERENCES devices(id),
 actor TEXT NOT NULL,job_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',
 result_json TEXT NOT NULL DEFAULT '',payload BLOB NOT NULL DEFAULT X'',
 reserve_bytes INTEGER NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
 payload_until INTEGER NOT NULL,dispatched_at INTEGER,finished_at INTEGER
);
CREATE INDEX file_jobs_device ON file_jobs(device_id,created_at DESC);
