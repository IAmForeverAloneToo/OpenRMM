-- Phase 2a: cases and their chain-of-custody log. Custody entries are
-- append-only (the triggers refuse changes and deletion), hash-chained per
-- case (internal/custody), and kept apart from the bounded audit log. Cases
-- are never deleted; they are closed.
CREATE TABLE cases (
 id TEXT PRIMARY KEY,
 title TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('open','closed')),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TABLE custody_entries (
 case_id TEXT NOT NULL REFERENCES cases(id),
 sequence INTEGER NOT NULL CHECK(sequence > 0),
 entry_json TEXT NOT NULL,
 hash TEXT NOT NULL,
 at INTEGER NOT NULL,
 device_id TEXT NOT NULL DEFAULT '',
 action TEXT NOT NULL,
 PRIMARY KEY (case_id, sequence)
) WITHOUT ROWID;
CREATE INDEX custody_device ON custody_entries(device_id, at) WHERE device_id <> '';
CREATE TRIGGER custody_append_only_update BEFORE UPDATE ON custody_entries BEGIN SELECT RAISE(ABORT, 'custody log is append-only'); END;
CREATE TRIGGER custody_append_only_delete BEFORE DELETE ON custody_entries BEGIN SELECT RAISE(ABORT, 'custody log is append-only'); END;
CREATE TRIGGER cases_kept BEFORE DELETE ON cases BEGIN SELECT RAISE(ABORT, 'cases are closed, not deleted'); END;
