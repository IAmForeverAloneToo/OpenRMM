-- YARA rule sets: the owner keeps named sets; each save is a new version,
-- checked by the engine before it is stored. A withdrawn set keeps its
-- versions for the record. Hunts and scans copy the rules they run.
CREATE TABLE yara_rule_sets (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 version INTEGER NOT NULL CHECK(version >= 1),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_by TEXT NOT NULL,
 updated_at INTEGER NOT NULL,
 withdrawn_at INTEGER
);
CREATE UNIQUE INDEX yara_rule_sets_name ON yara_rule_sets(lower(name)) WHERE withdrawn_at IS NULL;
CREATE TABLE yara_rule_versions (
 set_id TEXT NOT NULL REFERENCES yara_rule_sets(id),
 version INTEGER NOT NULL,
 source TEXT NOT NULL,
 sha256 TEXT NOT NULL,
 rules INTEGER NOT NULL,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY (set_id, version)
) WITHOUT ROWID;
-- The rules a hunt or scan runs, stored once by hash: each device's job
-- names the hash, and the rules are added when the job is handed out.
CREATE TABLE yara_sources (
 sha256 TEXT PRIMARY KEY,
 source TEXT NOT NULL,
 created_at INTEGER NOT NULL
) WITHOUT ROWID;
