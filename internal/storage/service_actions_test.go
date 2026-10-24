package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func actionFixture(t *testing.T) (*Store, Device, time.Time) {
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
	data, _ := json.Marshal(protocol.Services{Visibility: "queryable_services_only", Items: []protocol.WindowsService{{Name: "Example", DisplayName: "Example", State: "running", CanStart: true, CanStop: true}}})
	if e = s.RecordServices(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: winservices.Capability, Status: "ok", Data: data}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, now
}
func actionRequest(d Device, id string) ServiceAction {
	return ServiceAction{ServiceAction: protocol.ServiceAction{ID: id, Service: "Example", Action: "restart"}, DeviceID: d.ID, Actor: "admin"}
}
func TestActionsAreAtomicDeviceBoundAndNeverRedelivered(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	a := actionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := s.QueueServiceAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := s.QueueServiceAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal("duplicate request not idempotent", e)
	}
	if e := s.QueueServiceAction(ctx, actionRequest(d, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), now, time.Minute); !errors.Is(e, ErrAction) {
		t.Fatal("overlap accepted")
	}
	if _, e := s.DispatchServiceAction(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint dispatched")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now)
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
	if e := s.CompleteServiceAction(ctx, d.ID, "wrong", protocol.ServiceResult{ID: a.ID, Outcome: "succeeded", State: "running"}, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint completed")
	}
	r := protocol.ServiceResult{ID: a.ID, Outcome: "succeeded", State: "running"}
	for i := 0; i < 2; i++ {
		if e := s.CompleteServiceAction(ctx, d.ID, d.Fingerprint, r, now); e != nil {
			t.Fatal(e)
		}
	}
	r.State = "stopped"
	if e := s.CompleteServiceAction(ctx, d.ID, d.Fingerprint, r, now); !errors.Is(e, ErrAction) {
		t.Fatal("conflicting result accepted")
	}
	if e := s.QueueServiceAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal("finished duplicate failed")
	}
	v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now)
	if e != nil || v.Action != nil {
		t.Fatal("finished action replayed")
	}
	var audits int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='service_action_completed'").Scan(&audits)
	if audits != 1 {
		t.Fatal("duplicate completion audit")
	}
}
func TestActionExpiryRevocationAndStalePolicy(t *testing.T) {
	for _, mode := range []string{"queued_expiry", "dispatched_expiry", "revoked", "offline", "disabled", "unlisted", "self", "future_snapshot"} {
		t.Run(mode, func(t *testing.T) {
			s, d, now := actionFixture(t)
			ctx := context.Background()
			a := actionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			switch mode {
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-2*time.Minute).Unix())
			case "disabled":
				s.db.Exec("UPDATE device_services SET last_status='disabled'")
			case "unlisted":
				a.Service = "Other"
			case "self":
				a.Service = "OpenRMMAgent"
			case "future_snapshot":
				s.db.Exec("UPDATE device_services SET snapshot_at=?", now.Add(time.Second).Unix())
			}
			e := s.QueueServiceAction(ctx, a, now, time.Minute)
			if mode == "offline" || mode == "disabled" || mode == "unlisted" || mode == "self" || mode == "future_snapshot" {
				if !errors.Is(e, ErrAction) {
					t.Fatal("ineligible action accepted", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			expected := "expired"
			if mode == "dispatched_expiry" {
				s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now)
				expected = "unknown"
			}
			if mode == "revoked" {
				s.RevokeDevice(ctx, d.ID, now)
			}
			list, e := s.ServiceActions(ctx, d.ID, now.Add(91*time.Second))
			if e != nil || len(list) != 1 || list[0].Status != expected {
				t.Fatal("wrong terminal state", list, e)
			}
			if mode == "revoked" {
				if _, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now); !errors.Is(e, ErrAuthentication) {
					t.Fatal("revoked dispatch")
				}
			}
		})
	}
}

func TestDispatchedActionSurvivesReopenWithoutRedelivery(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	a := actionRequest(d, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e := s.QueueServiceAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if v, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now); e != nil || v.Action == nil {
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
	if v, e := again.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now.Add(time.Second)); e != nil || v.Action != nil {
		t.Fatal("restart replayed dispatch", e)
	}
	list, e := again.ServiceActions(ctx, d.ID, now.Add(90*time.Second))
	if e != nil || len(list) != 1 || list[0].Status != "unknown" {
		t.Fatal("ambiguous action not retained as unknown", e)
	}
}

func TestActionHistoryHasAHardBoundAndProtectsLiveIntentIDs(t *testing.T) {
	for _, recent := range []bool{false, true} {
		t.Run(fmt.Sprint(recent), func(t *testing.T) {
			s, d, now := actionFixture(t)
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
				_, e = tx.Exec(`INSERT INTO service_actions(id,device_id,service_name,action,actor,created_at,expires_at,status) VALUES(?,?,'Example','start','admin',?,?,'succeeded')`, fmt.Sprintf("%032x", i), d.ID, created, created+60)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = tx.Commit(); e != nil {
				t.Fatal(e)
			}
			e = s.QueueServiceAction(ctx, actionRequest(d, "ffffffffffffffffffffffffffffffff"), now, time.Minute)
			if recent && !errors.Is(e, ErrAction) {
				t.Fatal("live intent IDs pruned", e)
			}
			if !recent && e != nil {
				t.Fatal("old history did not make room", e)
			}
			var count int
			s.db.QueryRow("SELECT COUNT(*) FROM service_actions").Scan(&count)
			if count != 1000 {
				t.Fatal("hard action history bound lost", count)
			}
		})
	}
}
