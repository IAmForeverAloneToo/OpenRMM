package devices

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"testing"
	"time"
)

func TestEventQueriesAreCertificateBoundAndRevocable(t *testing.T) {
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
	q := storage.EventQuery{EventQuery: protocol.EventQuery{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Filter: protocol.EventFilter{Channel: "System", From: now.Add(-time.Hour).Unix(), To: now.Unix(), Level: -1, EventID: -1, Limit: 25}}, DeviceID: first.DeviceID, Actor: "admin"}
	if e = store.QueueEventQuery(ctx, q, *now, time.Minute); e != nil {
		t.Fatal(e)
	}
	v, e := s.PollEventQuery(ctx, state(t, second))
	if e != nil || v.Query != nil {
		t.Fatal("another device received query")
	}
	v, e = s.PollEventQuery(ctx, state(t, first))
	if e != nil || v.Query == nil {
		t.Fatal("owner query missing")
	}
	result := protocol.EventResult{ID: q.ID, Outcome: "ok", Events: []protocol.WindowsEvent{}}
	if _, e = s.EventQueryResult(ctx, state(t, second), result); !errors.Is(e, storage.ErrEventQuery) {
		t.Fatal("another device completed query")
	}
	if _, e = s.EventQueryResult(ctx, state(t, first), result); e != nil {
		t.Fatal(e)
	}
	store.RevokeDevice(ctx, first.DeviceID, *now)
	if _, e = s.PollEventQuery(ctx, state(t, first)); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked query accepted")
	}
	if _, e = s.EventQueryResult(ctx, state(t, first), result); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked result accepted")
	}
}
