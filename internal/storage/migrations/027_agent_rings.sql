CREATE TABLE agent_ring_policy (
 id INTEGER PRIMARY KEY CHECK(id=1),
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1)),
 pilot_groups TEXT NOT NULL DEFAULT '[]',
 delay_hours INTEGER NOT NULL DEFAULT 24 CHECK(delay_hours BETWEEN 1 AND 720),
 paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN(0,1)),
 pause_reason TEXT NOT NULL DEFAULT '',
 failures_since INTEGER NOT NULL DEFAULT 0,
 release_id TEXT NOT NULL DEFAULT '',
 pilot_done_at INTEGER,
 revision INTEGER NOT NULL DEFAULT 1
);
INSERT INTO agent_ring_policy(id) VALUES(1);
