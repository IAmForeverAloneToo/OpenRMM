package devices

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
	"testing"
	"time"
)

func TestServiceActionsUseMTLSDeviceAndRevocation(t *testing.T) {
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
	if _, e = s.Heartbeat(ctx, state(t, first), protocol.Heartbeat{Hostname: "test", OS: "windows", Architecture: "amd64", AgentVersion: "test"}); e != nil {
		t.Fatal(e)
	}
	data := json.RawMessage(`{"items":[{"name":"Example","display_name":"Example","state":"running","can_start":true,"can_stop":true}],"visibility":"queryable_services_only"}`)
	if _, e = s.Feature(ctx, state(t, first), protocol.FeatureReport{Capability: winservices.Capability, Status: "ok", Data: data}); e != nil {
		t.Fatal(e)
	}
	a := storage.ServiceAction{ServiceAction: protocol.ServiceAction{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Service: "Example", Action: "stop"}, DeviceID: first.DeviceID, Actor: "admin"}
	if e = store.QueueServiceAction(ctx, a, *now, time.Minute); e != nil {
		t.Fatal(e)
	}
	v, e := s.PollServiceAction(ctx, state(t, second))
	if e != nil || v.Action != nil {
		t.Fatal("other device claimed action")
	}
	v, e = s.PollServiceAction(ctx, state(t, first))
	if e != nil || v.Action == nil {
		t.Fatal("owner cannot claim")
	}
	result := protocol.ServiceResult{ID: a.ID, Outcome: "succeeded", State: "stopped"}
	if _, e = s.ServiceActionResult(ctx, state(t, second), result); !errors.Is(e, storage.ErrAction) {
		t.Fatal("cross-device result accepted")
	}
	if _, e = s.ServiceActionResult(ctx, state(t, first), result); e != nil {
		t.Fatal(e)
	}
	if e = store.RevokeDevice(ctx, first.DeviceID, *now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PollServiceAction(ctx, state(t, first)); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked poll accepted")
	}
	if _, e = s.ServiceActionResult(ctx, state(t, first), result); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked completion accepted")
	}
}
