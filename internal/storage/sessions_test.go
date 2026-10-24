package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sessions"
)

func sessionsReport(t *testing.T, list ...protocol.Session) protocol.FeatureReport {
	t.Helper()
	if list == nil {
		list = []protocol.Session{}
	}
	b, _ := json.Marshal(protocol.Sessions{Sessions: list})
	return protocol.FeatureReport{Capability: sessions.Capability, Status: "ok", Data: b}
}

func testSession(id uint32, user string, logon int64) protocol.Session {
	return protocol.Session{ID: id, User: user, Domain: "PC", State: "active", Connection: "console", Station: "Console", LogonAt: logon, IdleSeconds: -1}
}

// The history records each observed session once, with first and
// last seen and when it was gone; failed and out-of-order reports change
// nothing; another device's report never touches this one.
func TestSessionHistoryObservedAndBounded(t *testing.T) {
	ctx := context.Background()
	s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Unix(1800000000, 0)
	for i, d := range []Device{{ID: "0123456789abcdef0123456789abcdef", Fingerprint: "fp"}, {ID: "fedcba9876543210fedcba9876543210", Fingerprint: "fp2"}} {
		hash := fmt.Sprint("token", i)
		if e = s.NewEnrollmentToken(ctx, hash, now, now.Add(time.Hour)); e != nil {
			t.Fatal(e)
		}
		d.Hostname, d.OS, d.Architecture, d.Certificate = "pc", "windows", "amd64", "cert"
		if e = s.EnrollDevice(ctx, hash, d, now); e != nil {
			t.Fatal(e)
		}
	}
	id := "0123456789abcdef0123456789abcdef"
	if v, e := s.Sessions(ctx, id); e != nil || v.Status != "not_reported" {
		t.Fatal("initial state", v, e)
	}
	if e = s.RecordSessions(ctx, id, "wrong", sessionsReport(t), now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint accepted", e)
	}
	alice, bob := testSession(1, "alice", 1799990000), testSession(2, "bob", 1799999000)
	record := func(at time.Time, r protocol.FeatureReport) {
		t.Helper()
		if e := s.RecordSessions(ctx, id, "fp", r, at); e != nil {
			t.Fatal(e)
		}
	}
	record(now, sessionsReport(t, alice))
	record(now.Add(time.Minute), sessionsReport(t, alice, bob))
	record(now.Add(2*time.Minute), protocol.FeatureReport{Capability: sessions.Capability, Status: "failed"})
	record(now.Add(time.Second), sessionsReport(t)) // out of order: ignored
	alice.State = "disconnected"
	record(now.Add(3*time.Minute), sessionsReport(t, alice))
	if e = s.RecordSessions(ctx, "fedcba9876543210fedcba9876543210", "fp2", sessionsReport(t), now.Add(3*time.Minute)); e != nil {
		t.Fatal(e)
	}

	history, e := s.SessionHistory(ctx, id, now.Add(3*time.Minute))
	if e != nil || len(history) != 2 {
		t.Fatal("history", history, e)
	}
	byUser := map[string]SessionRecord{}
	for _, r := range history {
		byUser[r.Session.User] = r
	}
	a, b := byUser["alice"], byUser["bob"]
	if a.FirstSeenAt != now.Unix() || a.LastSeenAt != now.Add(3*time.Minute).Unix() || a.EndedAt != nil || a.Session.State != "disconnected" {
		t.Fatal("alice", a)
	}
	if b.FirstSeenAt != now.Add(time.Minute).Unix() || b.LastSeenAt != now.Add(time.Minute).Unix() || b.EndedAt == nil || *b.EndedAt != now.Add(3*time.Minute).Unix() {
		t.Fatal("bob", b)
	}
	if v, e := s.Sessions(ctx, id); e != nil || v.Status != "ok" || v.Data == nil || len(v.Data.Sessions) != 1 {
		t.Fatal("snapshot", v, e)
	}
	if other, _ := s.SessionHistory(ctx, "fedcba9876543210fedcba9876543210", now.Add(3*time.Minute)); len(other) != 0 {
		t.Fatal("devices not isolated")
	}

	// Only active sessions of fresh reports count as signed in.
	users, e := s.SignedInUsers(ctx, now.Add(3*time.Minute))
	if e != nil || len(users[id]) != 0 {
		t.Fatal("disconnected session listed as signed in", users, e)
	}
	alice.State = "active"
	record(now.Add(4*time.Minute), sessionsReport(t, alice))
	if users, _ = s.SignedInUsers(ctx, now.Add(4*time.Minute)); len(users[id]) != 1 || users[id][0] != `PC\alice` {
		t.Fatal("signed-in users", users)
	}
	if users, _ = s.SignedInUsers(ctx, now.Add(10*time.Minute)); len(users[id]) != 0 {
		t.Fatal("old report listed as signed in", users)
	}

	// Per-device cap and retention.
	at := now.Add(5 * time.Minute)
	for i := 0; i < SessionHistoryLimit+10; i++ {
		record(at.Add(time.Duration(i)*time.Second), sessionsReport(t, testSession(uint32(100+i), "user", int64(i))))
	}
	var n int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM session_history WHERE device_id=?", id).Scan(&n); e != nil || n != SessionHistoryLimit {
		t.Fatal("per-device cap", n, e)
	}
	if e = s.PruneSessionHistory(ctx, at.Add(SessionHistoryDays*24*time.Hour+time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = s.db.QueryRow("SELECT COUNT(*) FROM session_history").Scan(&n); e != nil || n != 0 {
		t.Fatal("retention", n, e)
	}
}
