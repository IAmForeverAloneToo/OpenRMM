-- New installations update agents automatically through the rings: pilot
-- groups first, every other device after the delay (24 hours by default),
-- and any failure pauses the rollout. Only a fresh database (no devices, the
-- ring policy never changed) is switched on; existing servers keep their
-- setting.
UPDATE agent_ring_policy SET enabled=1
WHERE id=1 AND revision=1 AND enabled=0 AND NOT EXISTS (SELECT 1 FROM devices);
