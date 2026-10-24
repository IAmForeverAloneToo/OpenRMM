CREATE TABLE script_schedules (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 device_id TEXT NOT NULL REFERENCES devices(id),
 version_id TEXT NOT NULL REFERENCES script_versions(id),
 name TEXT NOT NULL,
 arguments_json TEXT NOT NULL,
 start_at INTEGER NOT NULL,
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds=0 OR interval_seconds BETWEEN 300 AND 2592000),
 next_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN('active','paused','cancelled','completed')),
 revision INTEGER NOT NULL,
 actor TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE INDEX script_schedules_due ON script_schedules(state,next_at,id);
CREATE TABLE script_schedule_occurrences (
 id INTEGER PRIMARY KEY,
 schedule_id TEXT NOT NULL REFERENCES script_schedules(id),
 revision INTEGER NOT NULL,
 due_at INTEGER NOT NULL,
 recorded_at INTEGER NOT NULL,
 missed_count INTEGER NOT NULL DEFAULT 1,
 outcome TEXT NOT NULL,
 run_id TEXT REFERENCES script_runs(id) ON DELETE SET NULL,
 UNIQUE(schedule_id,revision,due_at)
);
CREATE INDEX script_schedule_occurrences_recent ON script_schedule_occurrences(schedule_id,recorded_at DESC,id DESC);
