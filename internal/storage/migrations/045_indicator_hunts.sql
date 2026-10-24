-- Phase 4.6: indicator hunts. The hunts table gains the kind 'indicators'
-- (SQLite cannot change a CHECK constraint, so the table is rebuilt; nothing
-- references it). Saved indicator lists can be reused by anyone with the
-- response permission; a hunt keeps its own copy of the indicators.
CREATE TABLE hunts_new (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('log_search','indicators')),
 case_id TEXT NOT NULL REFERENCES cases(id),
 actor TEXT NOT NULL,
 spec TEXT NOT NULL,
 problems_json TEXT NOT NULL DEFAULT '[]',
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 cancelled_at INTEGER
);
INSERT INTO hunts_new(id,kind,case_id,actor,spec,problems_json,created_at,expires_at,cancelled_at)
 SELECT id,kind,case_id,actor,spec,problems_json,created_at,expires_at,cancelled_at FROM hunts;
DROP TABLE hunts;
ALTER TABLE hunts_new RENAME TO hunts;
CREATE INDEX hunts_created ON hunts(created_at DESC);
CREATE TABLE ioc_lists (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 indicators_json TEXT NOT NULL,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_by TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX ioc_lists_name ON ioc_lists(lower(name));
