-- Audit events are kept by age (PruneAudit), no longer by count on each write.
CREATE INDEX audit_events_time ON audit_events(occurred_at);
