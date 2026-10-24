package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"sync"
	"testing"
	"time"
)

func updateFixture(t *testing.T) (*Store, Device, time.Time, UpdateJob) {
	s, d, now := actionFixture(t)
	raw, _ := json.Marshal(protocol.UpdateSupport{Broker: "available", CanInstall: true, CanRestart: true})
	if e := s.RecordUpdateSupport(context.Background(), d.ID, d.Fingerprint, protocol.FeatureReport{Capability: windowsupdate.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, now, UpdateJob{UpdateJob: protocol.UpdateJob{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: "scan", ExpiresAt: now.Add(time.Minute).Unix()}, DeviceID: d.ID, Actor: "admin"}
}
func TestUpdateJobDispatchIsolationProgressAndInstallSelection(t *testing.T) {
	s, d, now, q := updateFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if e := s.QueueUpdateJob(ctx, q, now, time.Minute); e != nil {
			t.Fatal(e)
		}
	}
	otherJob := q
	otherJob.ID = "dddddddddddddddddddddddddddddddd"
	if e := s.QueueUpdateJob(ctx, otherJob, now, time.Minute); !errors.Is(e, ErrUpdateJob) {
		t.Fatal("overlapping job accepted")
	}
	if _, e := s.DispatchUpdateJob(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong certificate accepted")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now)
			if e != nil {
				t.Error(e)
			}
			if r.Job != nil {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatal("dispatch repeated")
	}
	identity := protocol.UpdateIdentity{ID: "11111111-2222-3333-4444-555555555555", Revision: 1}
	p := protocol.UpdateProgress{ID: q.ID, Phase: "finished", Outcome: "ok", Catalog: []protocol.WindowsUpdate{{UpdateIdentity: identity, Title: "<script>untrusted</script>", KB: []string{"12345"}}}}
	for i := 0; i < 2; i++ {
		if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, p, now); e != nil {
			t.Fatal(e)
		}
	}
	other := p
	other.Outcome = "failed"
	other.Catalog = nil
	if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, other, now); !errors.Is(e, ErrUpdateJob) {
		t.Fatal("terminal result replaced")
	}
	install := q
	install.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	install.Action = "install"
	install.ScanID = q.ID
	install.Updates = []protocol.UpdateIdentity{identity}
	install.Updates[0].Revision = 2
	if e := s.QueueUpdateJob(ctx, install, now, time.Minute); !errors.Is(e, ErrUpdateJob) {
		t.Fatal("unscanned revision accepted")
	}
	install.Updates[0].Revision = 1
	if e := s.QueueUpdateJob(ctx, install, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now); e != nil {
		t.Fatal(e)
	}
	ip := protocol.UpdateProgress{ID: install.ID, Phase: "downloading", Total: 1}
	if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, ip, now); e != nil {
		t.Fatal(e)
	}
	ip.Phase = "finished"
	ip.Outcome = "ok"
	ip.Completed = 1
	ip.Items = []protocol.UpdateItemResult{{UpdateIdentity: identity, Outcome: "ok"}}
	if e := s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, ip, now); e != nil {
		t.Fatal(e)
	}
	jobs, e := s.UpdateJobs(ctx, d.ID, now)
	if e != nil || len(jobs) != 2 {
		t.Fatal("history", e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, ip, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked update completion")
	}
}
func TestUpdateJobEligibilityExpiryAndRestartPersistence(t *testing.T) {
	for _, mode := range []string{"disabled", "offline", "missing", "install_denied", "queued_expiry", "dispatch_expiry", "restart"} {
		t.Run(mode, func(t *testing.T) {
			s, d, now, q := updateFixture(t)
			ctx := context.Background()
			reject := false
			switch mode {
			case "disabled":
				s.db.Exec("UPDATE device_update_support SET last_status='disabled'")
				reject = true
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-2*time.Minute).Unix())
				reject = true
			case "missing":
				s.db.Exec(`UPDATE device_update_support SET snapshot_json='{"broker":"missing","can_install":false,"can_restart":false}'`)
				reject = true
			case "install_denied":
				q.Action = "restart"
				s.db.Exec(`UPDATE device_update_support SET snapshot_json='{"broker":"available","can_install":true,"can_restart":false}'`)
				reject = true
			}
			e := s.QueueUpdateJob(ctx, q, now, time.Minute)
			if reject {
				if !errors.Is(e, ErrUpdateJob) {
					t.Fatal("ineligible action", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode != "queued_expiry" {
				if _, e = s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "restart" {
				var path string
				s.db.QueryRow("PRAGMA database_list").Scan(new(int), new(string), &path)
				if e = s.Close(); e != nil {
					t.Fatal(e)
				}
				s, e = Open(ctx, path)
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
				dispatch, e := s.DispatchUpdateJob(ctx, d.ID, d.Fingerprint, now)
				if e != nil || dispatch.Job != nil {
					t.Fatal("restart redelivered job", e)
				}
			}
			jobs, e := s.UpdateJobs(ctx, d.ID, now.Add(21*time.Minute))
			want := "unknown"
			if mode == "queued_expiry" {
				want = "expired"
			}
			if e != nil || len(jobs) != 1 || jobs[0].Status != want {
				t.Fatal("expiry outcome", jobs, e)
			}
			late := protocol.UpdateProgress{ID: q.ID, Phase: "finished", Outcome: "ok"}
			if e = s.RecordUpdateProgress(ctx, d.ID, d.Fingerprint, late, now.Add(21*time.Minute)); !errors.Is(e, ErrUpdateJob) {
				t.Fatal("late result accepted")
			}
		})
	}
}

func TestUpdateHistoryCapacityPreservesRecentIntents(t *testing.T) {
	for _, recent := range []bool{false, true} {
		s, d, now, q := updateFixture(t)
		ctx := context.Background()
		created := now.Add(-3 * time.Minute).Unix()
		if recent {
			created = now.Unix()
		}
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 100; i++ {
			j := protocol.UpdateJob{ID: fmt.Sprintf("%032x", i), Action: "scan", ExpiresAt: now.Add(time.Minute).Unix()}
			raw, _ := json.Marshal(j)
			if _, e = tx.Exec("INSERT INTO update_jobs(id,device_id,actor,created_at,expires_at,status,request_json) VALUES(?,?,'admin',?,?,'succeeded',?)", j.ID, d.ID, created, now.Unix(), string(raw)); e != nil {
				t.Fatal(e)
			}
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		e = s.QueueUpdateJob(ctx, q, now, time.Minute)
		if recent && !errors.Is(e, ErrUpdateJob) {
			t.Fatal("recent intent pruned")
		}
		if !recent && e != nil {
			t.Fatal("old terminal history did not prune", e)
		}
		var n int
		s.db.QueryRow("SELECT COUNT(*) FROM update_jobs").Scan(&n)
		if n != 100 {
			t.Fatal("history exceeded bound", n)
		}
	}
}
