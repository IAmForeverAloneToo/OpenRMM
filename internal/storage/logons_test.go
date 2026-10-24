package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/logons"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Logons are stored once, filtered and paged newest first, and
// kept within retention and the per-device cap.
func TestLogonHistory(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	d := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "pc", OS: "windows", Architecture: "amd64", Certificate: "cert", Fingerprint: "fp"}
	if e = s.NewEnrollmentToken(ctx, "t", now, now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollDevice(ctx, "t", d, now); e != nil {
		t.Fatal(e)
	}
	send := func(v protocol.Logons, at time.Time, fp string) error {
		b, _ := json.Marshal(v)
		return s.RecordLogons(ctx, d.ID, fp, protocol.FeatureReport{Capability: logons.Capability, Status: "ok", Data: b}, at)
	}
	batch := protocol.Logons{Logons: []protocol.Logon{
		{RecordID: 1, Time: now.Add(-400 * 24 * time.Hour).Unix(), User: "old", Type: "interactive"},
		{RecordID: 2, Time: now.Add(-2 * time.Hour).Unix(), User: "alice", Domain: "PC", Type: "interactive"},
		{RecordID: 3, Time: now.Add(-time.Hour).Unix(), User: "bob_x", Domain: "CORP", Type: "remote", SourceIP: "192.0.2.5"},
		{RecordID: 4, Time: now.Add(-time.Hour).Unix(), User: "carol", Domain: "CORP", Type: "network_cleartext", SourceIP: "198.51.100.7"},
	}, More: true}
	if e = send(batch, now, "fp"); e != nil {
		t.Fatal(e)
	}
	// A repeated delivery adds nothing; an unknown certificate is refused.
	if e = send(batch, now.Add(time.Minute), "fp"); e != nil {
		t.Fatal(e)
	}
	if e = send(batch, now.Add(2*time.Minute), "other"); e == nil {
		t.Fatal("unknown certificate accepted")
	}
	list, more, e := s.Logons(ctx, d.ID, LogonFilter{}, now)
	if e != nil || more || len(list) != 3 || list[0].RecordID != 4 || list[1].RecordID != 3 || list[2].User != "alice" {
		t.Fatalf("history %+v %v %v", list, more, e)
	}
	st, e := s.LogonStatus(ctx, d.ID)
	if e != nil || st.Status != "ok" || !st.More || st.CollectedAt == nil || *st.CollectedAt != now.Add(time.Minute).Unix() {
		t.Fatalf("status %+v %v", st, e)
	}
	for f, want := range map[LogonFilter]int{
		{Kind: "network"}:                         1,
		{Kind: "remote"}:                          1,
		{Kind: "interactive"}:                     1,
		{Query: "corp\\bob"}:                      1,
		{Query: "_"}:                              1,
		{Query: "198.51"}:                         1,
		{Before: list[0].Time, Record: 4}:         2,
		{Before: list[0].Time, Record: 3}:         1,
		{Query: "corp", Before: list[0].Time + 1}: 2,
	} {
		got, _, e := s.Logons(ctx, d.ID, f, now)
		if e != nil || len(got) != want {
			t.Fatalf("filter %+v: %d %v", f, len(got), e)
		}
	}
	if _, _, e = s.Logons(ctx, d.ID, LogonFilter{Kind: "batch"}, now); e == nil {
		t.Fatal("invalid kind accepted")
	}
	// Retention removes logons from more than 365 days ago.
	if e = s.PruneLogonHistory(ctx, now.Add(365*24*time.Hour-90*time.Minute)); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = s.db.QueryRow(`SELECT COUNT(*) FROM logon_history`).Scan(&n); e != nil || n != 2 {
		t.Fatal("after prune", n, e)
	}
	// The per-device caps keep the newest logons; network logons are capped
	// on their own and never push out interactive ones.
	big := protocol.Logons{Logons: []protocol.Logon{}}
	for i := 0; i < logons.MaxLogons; i++ {
		big.Logons = append(big.Logons, protocol.Logon{RecordID: uint64(1000 + i), Time: now.Add(time.Duration(i) * time.Second).Unix(), User: "u", Type: "network"})
	}
	if e = send(big, now.Add(time.Hour), "fp"); e != nil {
		t.Fatal(e)
	}
	if e = s.db.QueryRow(`SELECT COUNT(*) FROM logon_history`).Scan(&n); e != nil || n != logons.MaxLogons+2 {
		t.Fatal("after batch", n, e)
	}
}
