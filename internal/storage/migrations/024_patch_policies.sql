CREATE TABLE patch_policies (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 revision INTEGER NOT NULL CHECK(revision>0),
 state TEXT NOT NULL CHECK(state IN('active','paused','archived')),
 definition_json TEXT NOT NULL,
 next_at INTEGER NOT NULL,
 actor TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TABLE patch_runs (
 id TEXT PRIMARY KEY CHECK(length(id)=32),
 policy_id TEXT NOT NULL REFERENCES patch_policies(id),
 revision INTEGER NOT NULL,
 device_id TEXT NOT NULL REFERENCES devices(id),
 scheduled_at INTEGER NOT NULL,
 window_end INTEGER NOT NULL,
 definition_json TEXT NOT NULL,
 status TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 scan_id TEXT NOT NULL DEFAULT '',
 install_id TEXT NOT NULL DEFAULT '',
 verify_id TEXT NOT NULL DEFAULT '',
 restart_id TEXT NOT NULL DEFAULT '',
 selected_json TEXT NOT NULL DEFAULT '[]',
 finished_at INTEGER,
 UNIQUE(policy_id,device_id,scheduled_at)
);
CREATE INDEX patch_runs_recent ON patch_runs(scheduled_at DESC,id);
CREATE INDEX patch_runs_active ON patch_runs(status);
CREATE TABLE patch_device_guards (
 device_id TEXT PRIMARY KEY REFERENCES devices(id),
 hold TEXT NOT NULL DEFAULT '',
 owner_run TEXT NOT NULL DEFAULT '',
 reboot_since INTEGER,
 defer_until INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 1
);
