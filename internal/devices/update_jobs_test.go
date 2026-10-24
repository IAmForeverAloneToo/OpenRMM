package devices

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"testing"
	"time"
)

func TestUpdateJobsAreCertificateBoundAndRevocable(t *testing.T) {
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
	data, _ := json.Marshal(protocol.UpdateSupport{Broker: "available"})
	if _, e = s.Feature(ctx, state(t, first), protocol.FeatureReport{Capability: windowsupdate.Capability, Status: "ok", Data: data}); e != nil {
		t.Fatal(e)
	}
	q := storage.UpdateJob{UpdateJob: protocol.UpdateJob{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: "scan", ExpiresAt: now.Add(time.Minute).Unix()}, DeviceID: first.DeviceID, Actor: "admin"}
	if e = store.QueueUpdateJob(ctx, q, *now, time.Minute); e != nil {
		t.Fatal(e)
	}
	v, e := s.PollUpdateJob(ctx, state(t, second))
	if e != nil || v.Job != nil {
		t.Fatal("another device received query")
	}
	v, e = s.PollUpdateJob(ctx, state(t, first))
	if e != nil || v.Job == nil {
		t.Fatal("owner query missing")
	}
	result := protocol.UpdateProgress{ID: q.ID, Phase: "finished", Outcome: "ok"}
	if _, e = s.UpdateJobProgress(ctx, state(t, second), result); !errors.Is(e, storage.ErrUpdateJob) {
		t.Fatal("another device completed query")
	}
	if _, e = s.UpdateJobProgress(ctx, state(t, first), result); e != nil {
		t.Fatal(e)
	}
	store.RevokeDevice(ctx, first.DeviceID, *now)
	if _, e = s.PollUpdateJob(ctx, state(t, first)); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked query accepted")
	}
	if _, e = s.UpdateJobProgress(ctx, state(t, first), result); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked result accepted")
	}
}
