CREATE TABLE technicians (
 id TEXT PRIMARY KEY CHECK(length(id)=32), username TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
 confirmed INTEGER NOT NULL DEFAULT 0 CHECK(confirmed IN(0,1)),
 password_hash TEXT NOT NULL DEFAULT '', totp_cipher BLOB NOT NULL DEFAULT X'',
 last_totp_step INTEGER NOT NULL DEFAULT -1,
 revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),
 access_json TEXT NOT NULL CHECK(json_valid(access_json)),
 invitation_hash TEXT UNIQUE, invitation_until INTEGER,
 created_at INTEGER NOT NULL
);
CREATE TABLE technician_recovery_codes (
 code_hash TEXT PRIMARY KEY, technician_id TEXT NOT NULL REFERENCES technicians(id) ON DELETE CASCADE
);
ALTER TABLE sessions ADD COLUMN technician_id TEXT REFERENCES technicians(id);
CREATE INDEX sessions_technician ON sessions(technician_id);
