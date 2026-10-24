package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"sync"
	"testing"
	"time"
)

func eventFixture(t *testing.T) (*Store, Device, time.Time, EventQuery) {
	s, d, now := actionFixture(t)
	data, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "denied"})
	if e := s.RecordEventLogs(context.Background(), d.ID, d.Fingerprint, protocol.FeatureReport{Capability: eventlogs.Capability, Status: "ok", Data: data}, now); e != nil {
		t.Fatal(e)
	}
	q := EventQuery{EventQuery: protocol.EventQuery{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Filter: protocol.EventFilter{Channel: "System", From: now.Add(-time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: -1, Limit: 25}}, DeviceID: d.ID, Actor: "admin"}
	return s, d, now, q
}
func TestEventQueryAuthorizationDispatchAndResults(t *testing.T) {
	s, d, now, q := eventFixture(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if e := s.QueueEventQuery(ctx, q, now, time.Minute); e != nil {
			t.Fatal(e)
		}
	}
	other := q
	other.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if e := s.QueueEventQuery(ctx, other, now, time.Minute); !errors.Is(e, ErrEventQuery) {
		t.Fatal("overlap accepted")
	}
	if _, e := s.DispatchEventQuery(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("other certificate dispatched")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := s.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now)
			if e != nil {
				t.Error(e)
			}
			if v.Query != nil {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatal("query delivered repeatedly")
	}
	r := protocol.EventResult{ID: q.ID, Outcome: "ok", Events: []protocol.WindowsEvent{{RecordID: 42, EventID: 1, Level: 2, Provider: "Example", Channel: "System", Time: now.Unix(), Message: "<script>secret event</script>", MessageStatus: "formatted", XML: "<Event/>"}}}
	if e := s.CompleteEventQuery(ctx, d.ID, "wrong", r, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("other certificate completed")
	}
	for i := 0; i < 2; i++ {
		if e := s.CompleteEventQuery(ctx, d.ID, d.Fingerprint, r, now); e != nil {
			t.Fatal(e)
		}
	}
	got, e := s.EventQuery(ctx, d.ID, q.ID, now)
	if e != nil || got.Result == nil || got.Status != "succeeded" {
		t.Fatal("result missing", e)
	}
	if _, e = s.EventQuery(ctx, "ffffffffffffffffffffffffffffffff", q.ID, now); !errors.Is(e, ErrEventQuery) {
		t.Fatal("cross-device result read")
	}
	var leak int
	s.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE target LIKE '%secret%' OR outcome LIKE '%secret%'").Scan(&leak)
	if leak != 0 {
		t.Fatal("event contents entered audit log")
	}
	if _, e = s.EventQuery(ctx, d.ID, q.ID, now.Add(15*time.Minute)); !errors.Is(e, ErrEventQuery) {
		t.Fatal("expired contents retained")
	}
	var rows int
	s.db.QueryRow("SELECT COUNT(*) FROM event_log_queries").Scan(&rows)
	if rows != 0 {
		t.Fatal("expired rows retained")
	}
}
func TestEventQueryFailuresExpiryAndPermissionGates(t *testing.T) {
	for _, mode := range []string{"denied", "disabled", "offline", "queued_expiry", "dispatch_expiry", "revoked", "future", "mismatched_result"} {
		t.Run(mode, func(t *testing.T) {
			s, d, now, q := eventFixture(t)
			ctx := context.Background()
			switch mode {
			case "denied":
				q.Filter.Channel = "Application"
			case "disabled":
				s.db.Exec("UPDATE device_event_logs SET last_status='disabled'")
			case "offline":
				s.db.Exec("UPDATE devices SET last_contact_at=?", now.Add(-2*time.Minute).Unix())
			case "future":
				s.db.Exec("UPDATE device_event_logs SET snapshot_at=?", now.Add(time.Second).Unix())
			}
			e := s.QueueEventQuery(ctx, q, now, time.Minute)
			if mode == "denied" || mode == "disabled" || mode == "offline" || mode == "future" {
				if !errors.Is(e, ErrEventQuery) {
					t.Fatal("ineligible query accepted", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			expected := "expired"
			if mode == "dispatch_expiry" || mode == "mismatched_result" {
				s.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now)
				expected = "unknown"
			}
			if mode == "revoked" {
				s.RevokeDevice(ctx, d.ID, now)
				if _, e = s.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now); !errors.Is(e, ErrAuthentication) {
					t.Fatal("revoked poll accepted")
				}
			}
			if mode == "mismatched_result" {
				r := protocol.EventResult{ID: q.ID, Outcome: "ok", Events: []protocol.WindowsEvent{{RecordID: 1, EventID: 1, Level: 1, Provider: "x", Channel: "System", Time: q.Filter.To + 100, MessageStatus: "unavailable"}}}
				if e = s.CompleteEventQuery(ctx, d.ID, d.Fingerprint, r, now); !errors.Is(e, ErrEventQuery) {
					t.Fatal("event outside the time range accepted")
				}
			}
			got, e := s.EventQuery(ctx, d.ID, q.ID, now.Add(61*time.Second))
			if e != nil || got.Status != expected {
				t.Fatal("wrong query expiry", got.Status, e)
			}
		})
	}
}

func TestEventQueryCacheBoundAndReopen(t *testing.T) {
	s, d, now, q := eventFixture(t)
	ctx := context.Background()
	if e := s.QueueEventQuery(ctx, q, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now); e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, path string
	s.db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path)
	s.Close()
	again, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	v, e := again.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now)
	if e != nil || v.Query != nil {
		t.Fatal("restart replayed query")
	}
	got, e := again.EventQuery(ctx, d.ID, q.ID, now.Add(time.Minute))
	if e != nil || got.Status != "unknown" {
		t.Fatal("interrupted query not unknown")
	}
	again.db.Exec("DELETE FROM event_log_queries")
	for i := 0; i < 100; i++ {
		f, _ := json.Marshal(q.Filter)
		if _, e := again.db.Exec(`INSERT INTO event_log_queries(id,device_id,actor,created_at,expires_at,status,filter_json) VALUES(?,?,'admin',?,?,'succeeded',?)`, fmt.Sprintf("%032x", i), d.ID, now.Unix(), now.Unix()+60, string(f)); e != nil {
			t.Fatal(e)
		}
	}
	q.ID = "ffffffffffffffffffffffffffffffff"
	if e := again.QueueEventQuery(ctx, q, now, time.Minute); !errors.Is(e, ErrEventQuery) {
		t.Fatal("unbounded event cache accepted")
	}
	if e := again.PruneEventQueries(ctx, now.Add(15*time.Minute)); e != nil {
		t.Fatal(e)
	}
	var count int
	again.db.QueryRow("SELECT COUNT(*) FROM event_log_queries").Scan(&count)
	if count != 0 {
		t.Fatal("retention sweep left contents")
	}
}

// Version 2 agents take any channel by name, raw XPath and larger
// pages; a probed channel must be readable; version 1 agents keep the old
// rules.
func TestEventQueryChannelsAndVersions(t *testing.T) {
	s, d, now, q := eventFixture(t)
	ctx := context.Background()
	record := func(version int, support protocol.EventLogSupport) {
		data, _ := json.Marshal(support)
		if e := s.RecordEventLogs(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: protocol.Capability{Name: "event_logs", Version: version}, Status: "ok", Data: data}, now); e != nil {
			t.Fatal(e)
		}
	}
	ids := 0
	try := func(f func(*protocol.EventFilter)) error {
		ids++
		v := q
		v.ID = fmt.Sprintf("%032x", ids)
		f(&v.Filter)
		e := s.QueueEventQuery(ctx, v, now, time.Minute)
		if e == nil {
			_, _ = s.db.Exec(`DELETE FROM event_log_queries WHERE id=?`, v.ID)
		}
		return e
	}
	security := func(f *protocol.EventFilter) { f.Channel = "Security" }
	big := func(f *protocol.EventFilter) { f.Limit = 250; f.XPath = "*[EventData[Data[@Name='LogonType']='10']]" }
	record(1, protocol.EventLogSupport{System: "readable", Application: "readable"})
	if try(security) == nil || try(big) == nil {
		t.Fatal("version 1 agent given a version 2 query")
	}
	record(2, protocol.EventLogSupport{System: "readable", Application: "denied", Channels: map[string]string{"Security": "readable", "Microsoft-Windows-Sysmon/Operational": "unavailable"}})
	for name, f := range map[string]func(*protocol.EventFilter){
		"security": security,
		"big":      big,
		"unprobed": func(f *protocol.EventFilter) { f.Channel = "Microsoft-Windows-DNS-Client/Operational" },
	} {
		if e := try(f); e != nil {
			t.Fatal(name, e)
		}
	}
	if try(func(f *protocol.EventFilter) { f.Channel = "Microsoft-Windows-Sysmon/Operational" }) == nil || try(func(f *protocol.EventFilter) { f.Channel = "Application" }) == nil {
		t.Fatal("unreadable probed channel queued")
	}
}
