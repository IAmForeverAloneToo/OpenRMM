-- Nightly server backups taken by the updater sidecar: on by default, at a
-- whole hour (UTC) chosen in the dashboard.
CREATE TABLE backup_settings(
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    hour INTEGER NOT NULL DEFAULT 3 CHECK (hour BETWEEN 0 AND 23),
    updated_at INTEGER,
    revision INTEGER NOT NULL DEFAULT 1
);
INSERT INTO backup_settings(id) VALUES (1);
