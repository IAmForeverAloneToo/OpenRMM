package windowsupdate

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowedBrokerBoundariesAndOldManualCompatibility(t *testing.T) {
	now := time.Now()
	q := testJob("scan")
	q.WindowStart = now.Add(-time.Minute).Unix()
	q.WindowEnd = now.Add(30 * time.Minute).Unix()
	if !JobValid(q) || !WindowAllows(q, now) {
		t.Fatal("valid window")
	}
	if WindowAllows(q, time.Unix(q.WindowStart-1, 0)) || WindowAllows(q, time.Unix(q.WindowEnd, 0)) {
		t.Fatal("outside window")
	}
	q.Action = "restart"
	if WindowAllows(q, time.Unix(q.WindowEnd-60, 0)) {
		t.Fatal("restart warning spills outside window")
	}
	q.Action = "scan"
	var calls atomic.Int32
	b, e := NewBroker(context.Background(), filepath.Join(t.TempDir(), "journal"), driverFunc(func(context.Context, protocol.UpdateJob, func(protocol.UpdateProgress) error) { calls.Add(1) }), true, true)
	if e != nil {
		t.Fatal(e)
	}
	b.now = func() time.Time { return now }
	if !b.Handle(IPCRequest{Op: "probe"}).Support.Windowed {
		t.Fatal("window support absent")
	}
	q.WindowStart = now.Add(time.Minute).Unix()
	q.WindowEnd = now.Add(31 * time.Minute).Unix()
	r := b.Handle(IPCRequest{Op: "submit", Job: &q})
	if r.Progress == nil || r.Progress.Outcome != "blocked" || calls.Load() != 0 {
		t.Fatal("early worker executed")
	}
	q = testJob("scan")
	if !JobValid(q) || !WindowAllows(q, now) {
		t.Fatal("manual job compatibility")
	}
}
