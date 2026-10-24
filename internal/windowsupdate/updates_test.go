package windowsupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var testIdentity = protocol.UpdateIdentity{ID: "11111111-2222-3333-4444-555555555555", Revision: 1}

func testJob(action string) protocol.UpdateJob {
	return protocol.UpdateJob{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: action, ExpiresAt: time.Now().Add(time.Minute).Unix()}
}

type driverFunc func(context.Context, protocol.UpdateJob, func(protocol.UpdateProgress) error)

func (f driverFunc) Run(c context.Context, q protocol.UpdateJob, e func(protocol.UpdateProgress) error) {
	f(c, q, e)
}
func TestBrokerPersistBeforeExecutionAndNeverReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	var calls atomic.Int32
	done := make(chan struct{})
	d := driverFunc(func(_ context.Context, q protocol.UpdateJob, emit func(protocol.UpdateProgress) error) {
		calls.Add(1)
		raw, e := os.ReadFile(path)
		if e != nil || len(raw) == 0 {
			t.Error("job not durable before execution")
		}
		p := Failure(q, "ok")
		p.Catalog = []protocol.WindowsUpdate{{UpdateIdentity: testIdentity, Title: "Update", KB: []string{}}}
		_ = emit(p)
		close(done)
	})
	b, e := NewBroker(context.Background(), path, d, true, false)
	if e != nil {
		t.Fatal(e)
	}
	q := testJob("scan")
	if r := b.Handle(IPCRequest{Op: "submit", Job: &q}); r.Progress == nil {
		t.Fatal(r.Error)
	}
	<-done
	for i := 0; i < 3; i++ {
		r := b.Handle(IPCRequest{Op: "submit", Job: &q})
		if r.Progress == nil || r.Progress.Outcome != "ok" {
			t.Fatal("lost terminal result")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("job repeated")
	}
	b, e = NewBroker(context.Background(), path, d, true, false)
	if e != nil {
		t.Fatal(e)
	}
	r := b.Handle(IPCRequest{Op: "status", ID: q.ID})
	if r.Progress == nil || r.Progress.Outcome != "ok" {
		t.Fatal("result did not survive restart")
	}
	install := testJob("install")
	install.ID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	install.ScanID = q.ID
	install.Updates = []protocol.UpdateIdentity{testIdentity}
	install.Updates[0].Revision = 2
	if r = b.Handle(IPCRequest{Op: "submit", Job: &install}); r.Error != "stale_scan" {
		t.Fatal("unscanned revision accepted")
	}
	restart := testJob("restart")
	restart.ID = install.ID
	if r = b.Handle(IPCRequest{Op: "submit", Job: &restart}); r.Progress == nil || r.Progress.Outcome != "denied" {
		t.Fatal("restart policy bypass")
	}
}
func TestBrokerInterruptedAndFailedJournal(t *testing.T) {
	q := testJob("install")
	q.ScanID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	q.Updates = []protocol.UpdateIdentity{testIdentity}
	p := filepath.Join(t.TempDir(), "journal.json")
	raw, _ := json.Marshal(journal{Version: 1, Records: []record{{q, time.Now().Unix(), initial(q)}}})
	if os.WriteFile(p, raw, 0600) != nil {
		t.Fatal("fixture")
	}
	b, e := NewBroker(context.Background(), p, driverFunc(func(context.Context, protocol.UpdateJob, func(protocol.UpdateProgress) error) {
		t.Error("interrupted install replayed")
	}), true, true)
	if e != nil {
		t.Fatal(e)
	}
	r := b.Handle(IPCRequest{Op: "status", ID: q.ID})
	if r.Progress == nil || r.Progress.Outcome != "unknown" {
		t.Fatal("interrupted work not unknown")
	}
	if r = b.Handle(IPCRequest{Op: "submit", Job: &q}); r.Progress == nil || r.Progress.Outcome != "unknown" {
		t.Fatal("interrupted work replayable")
	}
	if os.WriteFile(p, []byte(`{"version":1,"records":[{}]}`), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e = NewBroker(context.Background(), p, nil, true, true); e == nil {
		t.Fatal("corrupt journal accepted")
	}
}

func TestBrokerFailedPersistencePreventsExecution(t *testing.T) {
	var calls atomic.Int32
	b, e := NewBroker(context.Background(), filepath.Join(t.TempDir(), "absent", "journal.json"), driverFunc(func(context.Context, protocol.UpdateJob, func(protocol.UpdateProgress) error) { calls.Add(1) }), true, true)
	if e != nil {
		t.Fatal(e)
	}
	q := testJob("scan")
	r := b.Handle(IPCRequest{Op: "submit", Job: &q})
	if r.Error != "unavailable" || calls.Load() != 0 {
		t.Fatal("execution preceded durable journal")
	}
	if r = b.Handle(IPCRequest{Op: "probe"}); r.Error != "unavailable" {
		t.Fatal("failed journal did not fail closed")
	}
}
func TestUpdateValidationBoundsAndIdentity(t *testing.T) {
	q := testJob("install")
	q.ScanID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	q.Updates = []protocol.UpdateIdentity{testIdentity}
	if !JobValid(q) {
		t.Fatal("valid job")
	}
	q.Updates = append(q.Updates, testIdentity)
	if JobValid(q) {
		t.Fatal("duplicate selection")
	}
	q.Updates = q.Updates[:1]
	p := Failure(q, "partial")
	p.Completed = 1
	p.Items = []protocol.UpdateItemResult{{UpdateIdentity: testIdentity, Outcome: "ok"}}
	if !ProgressValid(p, q) {
		t.Fatal("valid result")
	}
	p.Items[0].Revision = 2
	if ProgressValid(p, q) {
		t.Fatal("result identity mismatch")
	}
	var s protocol.UpdateSupport
	if Decode([]byte(`{"broker":"available","shell":"cmd.exe"}`), &s) == nil {
		t.Fatal("unknown fields accepted")
	}
	if IdentityValid(protocol.UpdateIdentity{ID: "' or 1=1", Revision: 1}) {
		t.Fatal("criteria injection accepted")
	}
}
func FuzzUpdateProtocol(f *testing.F) {
	f.Add([]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","action":"scan","expires_at":100}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var q protocol.UpdateJob
		if Decode(b, &q) == nil && JobValid(q) {
			raw, e := json.Marshal(q)
			if e != nil {
				t.Fatal(e)
			}
			var again protocol.UpdateJob
			if Decode(raw, &again) != nil || !JobValid(again) {
				t.Fatal("unstable normalized job")
			}
		}
	})
}

func TestSanitizeKeepsTextAndReplacesControls(t *testing.T) {
	if s := Sanitize("2026-10 Update\x00 for\x1b x64\r\n\tKB1"); s != "2026-10 Update\uFFFD for\uFFFD x64\r\n\tKB1" || !text(s, 512) {
		t.Fatal("control characters not replaced", s)
	}
	if s := Sanitize("bad\xffutf8"); s != "bad\uFFFDutf8" {
		t.Fatal("invalid UTF-8 not replaced", s)
	}
	u := protocol.WindowsUpdate{UpdateIdentity: protocol.UpdateIdentity{ID: Sanitize("11111111-2222-3333-4444-55555555555\x01"), Revision: 1}, Title: "x", KB: []string{}}
	if ItemValid(u) {
		t.Fatal("sanitized identifier accepted")
	}
}
func TestBuildCatalogSkipsBadUpdates(t *testing.T) {
	id := func(i int) protocol.UpdateIdentity {
		return protocol.UpdateIdentity{ID: fmt.Sprintf("11111111-2222-3333-4444-%012d", i), Revision: 1}
	}
	results := []func() (protocol.WindowsUpdate, bool){
		func() (protocol.WindowsUpdate, bool) {
			return protocol.WindowsUpdate{UpdateIdentity: id(1), Title: "One", KB: []string{"5000001"}}, true
		},
		func() (protocol.WindowsUpdate, bool) { return protocol.WindowsUpdate{}, false },
		func() (protocol.WindowsUpdate, bool) {
			return protocol.WindowsUpdate{UpdateIdentity: id(1), Title: "Again", KB: []string{}}, true
		},
		func() (protocol.WindowsUpdate, bool) {
			return protocol.WindowsUpdate{UpdateIdentity: id(2), Title: "Two", KB: []string{"KB12"}}, true
		},
		func() (protocol.WindowsUpdate, bool) {
			return protocol.WindowsUpdate{UpdateIdentity: id(3), Title: "Three", KB: []string{}}, true
		},
	}
	catalog, truncated, skipped := BuildCatalog(len(results), func(j int) (protocol.WindowsUpdate, bool) { return results[j]() })
	if truncated || skipped != 3 || len(catalog) != 2 || catalog[0].Title != "One" || catalog[1].Title != "Three" {
		t.Fatal("bad updates not skipped", catalog, truncated, skipped)
	}
	q := testJob("scan")
	p := Failure(q, "ok")
	p.Catalog, p.Truncated, p.Skipped = catalog, truncated, skipped
	if !ProgressValid(p, q) {
		t.Fatal("scan with skipped updates rejected")
	}
	// Skipped results do not count toward the catalog limit.
	n := 2*MaxCatalog + 10
	catalog, truncated, skipped = BuildCatalog(n, func(j int) (protocol.WindowsUpdate, bool) {
		return protocol.WindowsUpdate{UpdateIdentity: id(j), Title: "U", KB: []string{}}, j%2 == 0
	})
	if len(catalog) != MaxCatalog || skipped != MaxCatalog-1 || !truncated {
		t.Fatal("catalog bound", len(catalog), skipped, truncated)
	}
}
func TestSkippedProgressBounds(t *testing.T) {
	q := testJob("scan")
	p := Failure(q, "ok")
	for _, n := range []int{-1, MaxScanned + 1} {
		p.Skipped = n
		if ProgressValid(p, q) {
			t.Fatal("invalid skip count accepted", n)
		}
	}
	p = Failure(q, "failed")
	p.Skipped = 1
	if ProgressValid(p, q) {
		t.Fatal("skip count on failed scan")
	}
	r := testJob("restart")
	p = Failure(r, "blocked")
	p.Skipped = 1
	if ProgressValid(p, r) {
		t.Fatal("skip count on restart")
	}
	var old protocol.UpdateProgress
	if Decode([]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","phase":"finished","outcome":"ok","hresult":0,"completed":0,"total":0,"reboot_known":false,"reboot_required":false,"catalog":[],"truncated":false,"items":null}`), &old) != nil || !ProgressValid(old, q) {
		t.Fatal("progress without skip count rejected")
	}
}
