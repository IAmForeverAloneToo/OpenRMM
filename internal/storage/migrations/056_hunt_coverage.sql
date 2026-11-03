-- What a hunt's YARA scan covered on each device, and the part of the
-- search the time limit stopped, kept with the cached result counts.
ALTER TABLE hunt_results ADD COLUMN stopped TEXT NOT NULL DEFAULT '';
ALTER TABLE hunt_results ADD COLUMN limit_minutes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hunt_results ADD COLUMN yara_files INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hunt_results ADD COLUMN yara_processes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hunt_results ADD COLUMN yara_unread INTEGER NOT NULL DEFAULT 0;
