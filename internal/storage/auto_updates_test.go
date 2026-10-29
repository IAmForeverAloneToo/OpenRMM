package storage

import (
	"context"
	"path/filepath"
	"testing"
)

// New installations update agents automatically through the rings; a server
// that already has devices keeps the setting it had.
func TestAutomaticAgentUpdatesDefault(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	if p, e := s.AgentRingPolicy(ctx); e != nil || !p.Enabled {
		t.Fatal("fresh install without automatic updates", p, e)
	}
	// An existing server: the migration runs again on a database with devices
	// and automatic updates off.
	for _, q := range []string{
		"DELETE FROM schema_migrations WHERE version>=49",
		"DROP TABLE mail_settings",
		"DROP TABLE backup_settings",
		"DROP INDEX audit_events_time",
		"UPDATE agent_ring_policy SET enabled=0 WHERE id=1",
		"INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES('00000000000000000000000000000001','pc','windows','amd64',1,'public','f')",
	} {
		if _, e = s.db.Exec(q); e != nil {
			t.Fatal(q, e)
		}
	}
	s.Close()
	if s, e = Open(ctx, path); e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if p, e := s.AgentRingPolicy(ctx); e != nil || p.Enabled {
		t.Fatal("existing server's setting changed", p, e)
	}
}
