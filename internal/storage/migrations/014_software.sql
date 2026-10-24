CREATE TABLE device_software (
 device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
 capability_version INTEGER NOT NULL,
 last_status TEXT NOT NULL CHECK(last_status IN ('ok','failed','disabled','unsupported')),
 reported_at INTEGER NOT NULL,
 snapshot_json TEXT NOT NULL DEFAULT '',
 snapshot_at INTEGER,
 baseline_ready INTEGER NOT NULL DEFAULT 0 CHECK(baseline_ready IN (0,1))
);
CREATE TABLE software_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 from_at INTEGER NOT NULL,
 observed_at INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('added','removed','version_changed','metadata_changed')),
 before_json TEXT NOT NULL,
 after_json TEXT NOT NULL
);
CREATE INDEX software_changes_device ON software_changes(device_id,id DESC);
CREATE INDEX software_changes_retention ON software_changes(observed_at,id);
