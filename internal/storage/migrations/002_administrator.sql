CREATE TABLE administrators (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_cipher BLOB NOT NULL,
    mfa_confirmed INTEGER NOT NULL CHECK (mfa_confirmed IN (0, 1)),
    last_totp_step INTEGER NOT NULL DEFAULT -1,
    credential_version INTEGER NOT NULL CHECK (credential_version > 0)
);
CREATE TABLE recovery_codes (
    code_hash TEXT PRIMARY KEY,
    administrator_id INTEGER NOT NULL REFERENCES administrators(id) ON DELETE CASCADE
);
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    administrator_id INTEGER NOT NULL REFERENCES administrators(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    credential_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL
);
