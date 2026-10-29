package devices

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// A waiting agent is answered as soon as work is queued for one of its idle
// kinds and the dashboard change is signalled; other devices and busy kinds
// are not woken.
func TestWorkWaitWakesForQueuedWork(t *testing.T) {
	s, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := s.NewToken(ctx)
	first, e := s.Enroll(ctx, request(t, token), "peer")
	if e != nil {
		t.Fatal(e)
	}
	token, _, _ = s.NewToken(ctx)
	second, e := s.Enroll(ctx, request(t, token), "peer")
	if e != nil {
		t.Fatal(e)
	}
	s.Heartbeat(ctx, state(t, first), protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"})
	data, _ := json.Marshal(protocol.EventLogSupport{System: "readable", Application: "readable"})
	if _, e = s.Feature(ctx, state(t, first), protocol.FeatureReport{Capability: eventlogs.Capability, Status: "ok", Data: data}); e != nil {
		t.Fatal(e)
	}
	idle := protocol.WorkWait{Idle: []string{protocol.WorkEvents, protocol.WorkFiles}}

	// Nothing queued: the wait ends empty after the hold.
	s.workHold = 300 * time.Millisecond
	start := time.Now()
	if r, e := s.WaitWork(ctx, state(t, first), idle); e != nil || len(r.Work) != 0 || time.Since(start) < 250*time.Millisecond {
		t.Fatal("empty wait", r, e)
	}

	// Work queued during a wait wakes it at once.
	s.workHold = 10 * time.Second
	done := make(chan protocol.WorkReply, 1)
	go func() {
		r, _ := s.WaitWork(ctx, state(t, first), idle)
		done <- r
	}()
	time.Sleep(200 * time.Millisecond)
	q := storage.EventQuery{EventQuery: protocol.EventQuery{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Filter: protocol.EventFilter{Channel: "System", From: now.Add(-time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: -1, Limit: 25}}, DeviceID: first.DeviceID, Actor: "admin"}
	if e = store.QueueEventQuery(ctx, q, *now, time.Minute); e != nil {
		t.Fatal(e)
	}
	s.Notify(first.DeviceID)
	select {
	case r := <-done:
		if !slices.Equal(r.Work, []string{protocol.WorkEvents}) {
			t.Fatal("wrong work", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting agent not woken")
	}

	// Another device, and a kind the agent is busy with, see nothing.
	s.workHold = 300 * time.Millisecond
	if r, e := s.WaitWork(ctx, state(t, second), idle); e != nil || len(r.Work) != 0 {
		t.Fatal("another device woken", r, e)
	}
	if r, e := s.WaitWork(ctx, state(t, first), protocol.WorkWait{Idle: []string{protocol.WorkFiles}}); e != nil || len(r.Work) != 0 {
		t.Fatal("busy kind reported", r, e)
	}
	// Queued work is reported at once, without a signal.
	if r, e := s.WaitWork(ctx, state(t, first), idle); e != nil || !slices.Equal(r.Work, []string{protocol.WorkEvents}) {
		t.Fatal("queued work not reported", r, e)
	}
	// An idle terminal the hub has not seen yet is asked to exchange.
	if r, e := s.WaitWork(ctx, state(t, first), protocol.WorkWait{Idle: []string{protocol.WorkTerminal}}); e != nil || !slices.Equal(r.Work, []string{protocol.WorkTerminal}) {
		t.Fatal("terminal presence not requested", r, e)
	}
	if _, e := s.WaitWork(ctx, state(t, first), protocol.WorkWait{Idle: []string{"files", "files"}}); !errors.Is(e, ErrWork) {
		t.Fatal("invalid wait accepted", e)
	}
}
