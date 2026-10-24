CREATE TABLE metric_receipts (
 device_id TEXT NOT NULL REFERENCES devices(id),
 kind TEXT NOT NULL CHECK(kind IN('cpu','memory','disk_space')),
 last_at INTEGER NOT NULL,
 PRIMARY KEY(device_id,kind)
) WITHOUT ROWID;
CREATE TABLE metric_buckets (
 device_id TEXT NOT NULL REFERENCES devices(id),
 kind TEXT NOT NULL CHECK(kind IN('cpu','memory','disk_space')),
 step INTEGER NOT NULL CHECK(step IN(300,3600)),
 bucket INTEGER NOT NULL,
 valid_count INTEGER NOT NULL DEFAULT 0,
 unknown_count INTEGER NOT NULL DEFAULT 0,
 gap_count INTEGER NOT NULL DEFAULT 0,
 sum_value REAL NOT NULL DEFAULT 0,
 min_value REAL,
 max_value REAL,
 first_at INTEGER NOT NULL,
 last_at INTEGER NOT NULL,
 PRIMARY KEY(device_id,kind,step,bucket)
) WITHOUT ROWID;
CREATE INDEX metric_retention ON metric_buckets(step,bucket,device_id,kind);
