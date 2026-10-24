CREATE TABLE device_authority (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    fingerprint TEXT NOT NULL
);
CREATE TABLE enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    architecture TEXT NOT NULL,
    enrolled_at INTEGER NOT NULL,
    revoked_at INTEGER,
    certificate_pem TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    previous_fingerprint TEXT NOT NULL DEFAULT '',
    previous_until INTEGER NOT NULL DEFAULT 0
);
ALTER TABLE audit_events ADD COLUMN target TEXT NOT NULL DEFAULT '';
