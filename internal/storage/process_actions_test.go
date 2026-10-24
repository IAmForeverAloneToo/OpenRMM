package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func processActionFixture(t *testing.T) (*Store, Device, time.Time) {
	t.Helper()
	s, e := Open(context.Background(), filepath.Join(t.TempDir(), "data", "db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Unix(1800000000, 0)
	d := Device{ID: "0123456789abcdef0123456789abcdef", Hostname: "test", OS: "windows", Architecture: "amd64", Certificate: "public", Fingerprint: "fp"}
	ctx := context.Background()
	if e = s.NewEnrollmentToken(ctx, "token", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollDevice(ctx, "token", d, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordHeartbeat(ctx, d.ID, d.Fingerprint, protocol.Heartbeat{Hostname: d.Hostname, OS: d.OS, Architecture: d.Architecture, AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(protocol.Processes{Coverage: processes.Coverage, Items: []protocol.Process{{PID: 1234, Start: "123456", Name: "fixture.exe", CanTerminate: true}}})
	if e = s.RecordProcesses(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: processes.Capability, Status: "ok", Data: data}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, now
}
func processActionRequest(d Device, id string) ProcessAction {
	return ProcessAction{ProcessAction: protocol.ProcessAction{ID: id, PID: 1234, Start: "123456", Name: "fixture.exe"}, DeviceID: d.ID, Actor: "admin"}
}
func TestProcessActionsAreAtomicDeviceBoundAndNeverRedelivered(t *testing.T) {
	s, d, now := processActionFixture(t)
	ctx := context.Background()
	a := processActionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := s.QueueProcessAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := s.QueueProcessAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal("duplicate request not idempotent", e)
	}
	if e := s.QueueProcessAction(ctx, processActionRequest(d, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), now, time.Minute); !errors.Is(e, ErrProcessAction) {
		t.Fatal("overlap accepted")
	}
	if _, e := s.DispatchProcessAction(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint dispatched")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now)
			if e != nil {
				t.Error(e)
			}
			if v.Action != nil {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatal("action dispatched repeatedly", count)
	}
	if e := s.CompleteProcessAction(ctx, d.ID, "wrong", protocol.ProcessResult{ID: a.ID, Outcome: "succeeded"}, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint completed")
	}
	r := protocol.ProcessResult{ID: a.ID, Outcome: "succeeded"}
	for i := 0; i < 2; i++ {
		if e := s.CompleteProcessAction(ctx, d.ID, d.Fingerprint, r, now); e != nil {
			t.Fatal(e)
		}
	}
	r.Outcome = "failed"
	if e := s.CompleteProcessAction(ctx, d.ID, d.Fingerprint, r, now); !errors.Is(e, ErrProcessAction) {
		t.Fatal("conflicting result accepted")
	}
	if e := s.QueueProcessAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal("finished duplicate failed")
	}
	v, e := s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now)
	if e != nil || v.Action != nil {
		t.Fatal("finished action replayed")
	}
	var audits int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='process_action_completed'").Scan(&audits)
	if audits != 1 {
		t.Fatal("duplicate completion audit")
	}
}
func TestProcessActionExpiryRevocationAndStalePolicy(t *testing.T) {
	for _, mode := range []string{"queued_expiry", "dispatched_expiry", "revoked", "offline", "disabled", "unlisted", "self", "future_snapshot"} {
		t.Run(mode, func(t *testing.T) {
			s, d, now := processActionFixture(t)
			ctx := context.Background()
			a := processActionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			switch mode {
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-2*time.Minute).Unix())
			case "disabled":
				s.db.Exec("UPDATE device_processes SET last_status='disabled'")
			case "unlisted":
				a.Name = "Other.exe"
			case "self":
				a.Name = "OpenRMM-Agent.exe"
			case "future_snapshot":
				s.db.Exec("UPDATE device_processes SET snapshot_at=?", now.Add(time.Second).Unix())
			}
			e := s.QueueProcessAction(ctx, a, now, time.Minute)
			if mode == "offline" || mode == "disabled" || mode == "unlisted" || mode == "self" || mode == "future_snapshot" {
				if !errors.Is(e, ErrProcessAction) {
					t.Fatal("ineligible action accepted", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			expected := "expired"
			if mode == "dispatched_expiry" {
				s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now)
				expected = "unknown"
			}
			if mode == "revoked" {
				s.RevokeDevice(ctx, d.ID, now)
			}
			list, e := s.ProcessActions(ctx, d.ID, now.Add(91*time.Second))
			if e != nil || len(list) != 1 || list[0].Status != expected {
				t.Fatal("wrong terminal state", list, e)
			}
			if mode == "revoked" {
				if _, e := s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now); !errors.Is(e, ErrAuthentication) {
					t.Fatal("revoked dispatch")
				}
			}
		})
	}
}

func TestDispatchedProcessActionSurvivesReopenWithoutRedelivery(t *testing.T) {
	s, d, now := processActionFixture(t)
	ctx := context.Background()
	a := processActionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := s.QueueProcessAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if v, e := s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now); e != nil || v.Action == nil {
		t.Fatal("dispatch failed", e)
	}
	var path string
	var seq int
	var name string
	if e := s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	again, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if v, e := again.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now.Add(time.Second)); e != nil || v.Action != nil {
		t.Fatal("restart replayed dispatch", e)
	}
	list, e := again.ProcessActions(ctx, d.ID, now.Add(90*time.Second))
	if e != nil || len(list) != 1 || list[0].Status != "unknown" {
		t.Fatal("ambiguous action not retained as unknown", e)
	}
}

func TestProcessActionHistoryHasAHardBoundAndProtectsLiveIntentIDs(t *testing.T) {
	for _, recent := range []bool{false, true} {
		t.Run(fmt.Sprint(recent), func(t *testing.T) {
			s, d, now := processActionFixture(t)
			ctx := context.Background()
			created := now.Add(-3 * time.Minute).Unix()
			if recent {
				created = now.Unix()
			}
			tx, e := s.db.Begin()
			if e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 1000; i++ {
				_, e = tx.Exec(`INSERT INTO process_actions(id,device_id,pid,start,name,actor,created_at,expires_at,status) VALUES(?,?,1234,'123456','fixture.exe','admin',?,?,'succeeded')`, fmt.Sprintf("%032x", i), d.ID, created, created+60)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			e = s.QueueProcessAction(ctx, processActionRequest(d, "ffffffffffffffffffffffffffffffff"), now, time.Minute)
			if recent && !errors.Is(e, ErrProcessAction) {
				t.Fatal("live intent IDs pruned", e)
			}
			if !recent && e != nil {
				t.Fatal("old history did not make room", e)
			}
			var count int
			s.db.QueryRow("SELECT COUNT(*) FROM process_actions").Scan(&count)
			if count != 1000 {
				t.Fatal("hard action history bound lost", count)
			}
		})
	}
}
