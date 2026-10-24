CREATE TABLE script_batches (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 version_id TEXT NOT NULL REFERENCES script_versions(id),
 name TEXT NOT NULL,
 actor TEXT NOT NULL,
 request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
 change_json TEXT NOT NULL,
 targets_json TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 restored INTEGER NOT NULL DEFAULT 0 CHECK(restored IN(0,1))
);
CREATE INDEX script_batches_recent ON script_batches(created_at DESC,id);
