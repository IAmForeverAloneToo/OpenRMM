package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"strings"
	"sync"
	"testing"
	"time"
)

func scriptFixture(t *testing.T) (*Store, Device, ScriptVersion, time.Time) {
	t.Helper()
	s, d, now := processActionFixture(t)
	ctx := context.Background()
	v, e := s.CreateScriptVersion(ctx, ScriptVersion{ScriptVersion: protocol.ScriptVersion{ID: strings.Repeat("d", 32), ScriptID: strings.Repeat("e", 32), Definition: protocol.ScriptDefinition{Name: "Fixture", Description: "Test", Body: "param([string]$Message)\nWrite-Output $Message", Parameters: []protocol.ScriptParameter{{Name: "Message", Required: true}}, Timeout: 5, RunAs: "restricted"}}, Actor: "admin"}, now)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "enabled"})
	if e = s.RecordScriptSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: data}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, v, now
}
func scriptRequest(d Device, v ScriptVersion, id string) ScriptRun {
	return ScriptRun{ScriptJob: protocol.ScriptJob{ID: id, Version: protocol.ScriptVersion{ID: v.ID}, Arguments: map[string]string{"Message": "private parameter"}}, DeviceID: d.ID, Actor: "admin"}
}
func TestScriptImmutableVersionsAndConcurrentNumbering(t *testing.T) {
	s, _, v, now := scriptFixture(t)
	ctx := context.Background()
	oldHash := v.Hash
	changed := v
	changed.Definition.Body = "Write-Output changed"
	if _, e := s.CreateScriptVersion(ctx, changed, now); e == nil {
		t.Fatal("existing version overwritten")
	}
	stored, e := s.ScriptVersion(ctx, v.ID)
	if e != nil || stored.Hash != oldHash || stored.Definition.Body != v.Definition.Body {
		t.Fatal("immutable version changed")
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			x := v
			x.ID = fmt.Sprintf("%032x", i+100)
			if _, e := s.CreateScriptVersion(ctx, x, now); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	versions, e := s.ScriptVersions(ctx, v.ScriptID)
	if e != nil || len(versions) != 5 {
		t.Fatal("version history", e)
	}
	for i, x := range versions {
		if x.Number != 5-i || !scripting.VersionValid(x.ScriptVersion) {
			t.Fatal("version numbering/hash")
		}
		if i < 4 && x.Hash == oldHash {
			t.Fatal("new immutable version reused approval hash")
		}
	}
	latest, e := s.ScriptVersions(ctx, "")
	if e != nil || len(latest) != 1 || latest[0].Number != 5 {
		t.Fatal("latest library", e)
	}
}
func TestScriptRunAtomicDispatchCancelAndResultIdempotency(t *testing.T) {
	s, d, v, now := scriptFixture(t)
	ctx := context.Background()
	r := scriptRequest(d, v, strings.Repeat("a", 32))
	for range 2 {
		if e := s.QueueScriptRun(ctx, r, now, time.Minute); e != nil {
			t.Fatal(e)
		}
	}
	wrong := r
	wrong.Arguments = map[string]string{"Message": "other"}
	if e := s.QueueScriptRun(ctx, wrong, now, time.Minute); !errors.Is(e, ErrScript) {
		t.Fatal("conflicting retry")
	}
	if _, e := s.DispatchScriptRun(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong fingerprint")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, now)
			if e != nil {
				t.Error(e)
			}
			if q.Job != nil {
				mu.Lock()
				count++
				mu.Unlock()
				if !scripting.JobValid(*q.Job) || q.Job.Version.Hash != v.Hash {
					t.Error("invalid delivered version")
				}
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatal("redelivery", count)
	}
	if _, e := s.UpdateScriptRun(ctx, d.ID, "wrong", scripting.Failure(r.ID, "running"), now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong result identity")
	}
	if _, e := s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, scripting.Failure(r.ID, "running"), now); e != nil {
		t.Fatal(e)
	}
	if e := s.CancelScriptRun(ctx, d.ID, r.ID, "admin", now); e != nil {
		t.Fatal(e)
	}
	if cancel, e := s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, scripting.Failure(r.ID, "running"), now); e != nil || !cancel {
		t.Fatal("cancel not delivered", e)
	}
	result := scripting.Failure(r.ID, "cancelled")
	for range 2 {
		if _, e := s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, result, now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, scripting.Failure(r.ID, "unknown"), now); !errors.Is(e, ErrScript) {
		t.Fatal("conflicting result")
	}
	stored, e := s.ScriptRun(ctx, d.ID, r.ID, now)
	if e != nil || stored.Status != "cancelled" || !stored.CancelRequested {
		t.Fatal("cancelled run", e)
	}
	var audits int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action='script_run_cancelled'").Scan(&audits)
	if audits != 1 {
		t.Fatal("duplicate terminal audit", audits)
	}
	var leaked int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE target LIKE '%private parameter%' OR outcome LIKE '%private parameter%'").Scan(&leaked)
	if leaked != 0 {
		t.Fatal("parameter in audit")
	}
}
func TestScriptEligibilityExpiryUnknownAndQueuedCancellation(t *testing.T) {
	for _, mode := range []string{"offline", "disabled", "stale", "future", "bad_parameter", "reused_version", "queued_cancel", "expiry", "lost_dispatch", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			s, d, v, now := scriptFixture(t)
			ctx := context.Background()
			r := scriptRequest(d, v, strings.Repeat("a", 32))
			invalid := true
			switch mode {
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-2*time.Minute).Unix())
			case "disabled":
				s.db.Exec("UPDATE device_script_support SET last_status='disabled'")
			case "stale":
				s.db.Exec("UPDATE device_script_support SET reported_at=?", now.Add(-2*time.Minute).Unix())
			case "future":
				s.db.Exec("UPDATE device_script_support SET reported_at=?", now.Add(time.Second).Unix())
			case "bad_parameter":
				r.Arguments = map[string]string{"Injection": "code"}
			case "reused_version":
				r.Version.ID = strings.Repeat("f", 32)
			default:
				invalid = false
			}
			e := s.QueueScriptRun(ctx, r, now, time.Minute)
			if invalid {
				if !errors.Is(e, ErrScript) {
					t.Fatal("ineligible run accepted", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "queued_cancel":
				if e = s.CancelScriptRun(ctx, d.ID, r.ID, "admin", now); e != nil {
					t.Fatal(e)
				}
				q, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, now)
				if e != nil || q.Job != nil {
					t.Fatal("cancelled job dispatched")
				}
			case "lost_dispatch":
				_, e = s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, now)
				if e != nil {
					t.Fatal(e)
				}
			case "revoked":
				s.RevokeDevice(ctx, d.ID, now)
			}
			list, e := s.ScriptRuns(ctx, d.ID, now.Add(time.Minute))
			if e != nil || len(list) != 1 {
				t.Fatal(e)
			}
			want := "expired"
			if mode == "queued_cancel" {
				want = "cancelled"
			}
			if mode == "lost_dispatch" {
				want = "unknown"
			}
			if list[0].Status != want {
				t.Fatal("unexpected outcome", list[0].Status, want)
			}
		})
	}
}
