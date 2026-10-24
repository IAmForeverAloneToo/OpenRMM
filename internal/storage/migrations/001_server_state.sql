CREATE TABLE server_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
