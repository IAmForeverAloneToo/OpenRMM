-- Alert e-mail configured from the dashboard: one row, off until set. The
-- SMTP password is stored encrypted with the server's separate encryption key.
CREATE TABLE mail_settings(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    host TEXT NOT NULL DEFAULT '' CHECK (length(host) <= 253),
    port INTEGER NOT NULL DEFAULT 587 CHECK (port BETWEEN 1 AND 65535),
    tls TEXT NOT NULL DEFAULT 'starttls' CHECK (tls IN ('starttls', 'tls')),
    username TEXT NOT NULL DEFAULT '' CHECK (length(username) <= 256),
    password_cipher BLOB,
    from_address TEXT NOT NULL DEFAULT '' CHECK (length(from_address) <= 254),
    recipients_json TEXT NOT NULL DEFAULT '[]' CHECK (length(recipients_json) <= 4096),
    server_url TEXT NOT NULL DEFAULT '' CHECK (length(server_url) <= 253),
    updated_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 1
);
INSERT INTO mail_settings(id) VALUES (1);
