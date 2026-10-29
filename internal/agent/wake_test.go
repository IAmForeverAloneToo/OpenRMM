package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// An idle worker sleeps until woken while the server answers waits, and is
// listed as idle meanwhile; otherwise it keeps its own interval.
func TestWakerIdleWorkers(t *testing.T) {
	w := newWaker()
	start := time.Now()
	if !w.waiter(protocol.WorkFiles)(context.Background(), 20*time.Millisecond) || time.Since(start) > time.Second {
		t.Fatal("inactive waiter did not use its interval")
	}
	w.active.Store(true)
	done := make(chan bool, 1)
	go func() { done <- w.waiter(protocol.WorkFiles)(context.Background(), idleCheck) }()
	for i := 0; ; i++ {
		if idle, _ := w.snapshot(); slices.Equal(idle, []string{protocol.WorkFiles}) {
			break
		}
		if i > 200 {
			t.Fatal("waiting worker not listed as idle")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("idle worker did not wait for a wake")
	case <-time.After(100 * time.Millisecond):
	}
	w.wake(protocol.WorkFiles)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("woken worker kept waiting")
	}
	if idle, _ := w.snapshot(); len(idle) != 0 {
		t.Fatal("woken worker still listed as idle", idle)
	}
	// Longer waits (backing off after failures) are not replaced.
	start = time.Now()
	w.waiter(protocol.WorkFiles)(context.Background(), idleCheck+time.Millisecond)
	if time.Since(start) < idleCheck {
		t.Fatal("backoff shortened")
	}
}

// The wait loop wakes the workers the server names; a server without waits
// leaves the workers on their intervals.
func TestRunWake(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/work" {
			http.NotFound(w, r)
			return
		}
		var in protocol.WorkWait
		if json.NewDecoder(r.Body).Decode(&in) != nil || !in.Valid() {
			http.Error(w, "bad", 400)
			return
		}
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(protocol.WorkReply{Work: []string{protocol.WorkScripts}})
			return
		}
		<-r.Context().Done()
	}))
	defer srv.Close()
	s := &heartbeatSession{transport: srv.Client().Transport.(*http.Transport)}
	s.value.DeviceURL = srv.URL
	w := newWaker()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { s.runWake(ctx, w); close(stopped) }()
	select {
	case <-w.signals[protocol.WorkScripts]:
	case <-time.After(5 * time.Second):
		t.Fatal("named worker not woken")
	}
	if !w.active.Load() {
		t.Fatal("answered waits not recorded")
	}
	cancel()
	<-stopped

	old := httptest.NewTLSServer(http.NotFoundHandler())
	defer old.Close()
	s = &heartbeatSession{transport: old.Client().Transport.(*http.Transport)}
	s.value.DeviceURL = old.URL
	w = newWaker()
	w.active.Store(true)
	w.setIdle(protocol.WorkFiles, time.Now().Add(time.Hour))
	ctx, cancel = context.WithCancel(context.Background())
	stopped = make(chan struct{})
	go func() { s.runWake(ctx, w); close(stopped) }()
	select {
	case <-w.signals[protocol.WorkFiles]:
	case <-time.After(5 * time.Second):
		t.Fatal("workers not released for an older server")
	}
	if w.active.Load() {
		t.Fatal("older server treated as answering waits")
	}
	cancel()
	<-stopped
}

// An idle companion is answered locally; changes, a wake and the minute
// refresh reach the server.
func TestDesktopRelayQuiet(t *testing.T) {
	w := newWaker()
	var d desktopRelay
	idle := desktop.Exchange{Ready: true, Peer: "p", Displays: []desktop.Display{{Width: 1920, Height: 1080, Primary: true}}}
	if d.quiet(w, idle) {
		t.Fatal("quiet without waits")
	}
	w.active.Store(true)
	if d.quiet(w, idle) {
		t.Fatal("first exchange answered locally")
	}
	d.forwarded(idle, desktop.Reply{})
	if !d.quiet(w, idle) {
		t.Fatal("unchanged idle exchange forwarded")
	}
	if got, _ := w.snapshot(); !slices.Contains(got, protocol.WorkDesktop) {
		t.Fatal("connected companion not listed as idle")
	}
	moved := idle
	moved.Displays = []desktop.Display{{Width: 2560, Height: 1440, Primary: true}}
	if d.quiet(w, moved) {
		t.Fatal("display change answered locally")
	}
	w.wake(protocol.WorkDesktop)
	if d.quiet(w, idle) {
		t.Fatal("woken relay answered locally")
	}
	d.forwarded(idle, desktop.Reply{Request: &desktop.Request{}})
	if d.quiet(w, idle) {
		t.Fatal("running session answered locally")
	}
	d.forwarded(idle, desktop.Reply{})
	d.at = time.Now().Add(-2 * time.Minute)
	if d.quiet(w, idle) {
		t.Fatal("minute refresh skipped")
	}
}
