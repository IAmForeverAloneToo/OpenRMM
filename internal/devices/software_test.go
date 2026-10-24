package devices

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestSoftwareIdentitySchemaAndFreshness(t *testing.T) {
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
	r := protocol.FeatureReport{Capability: software.CapabilityV1, Status: "ok", Data: json.RawMessage(`{"coverage":"machine_uninstall_registry_32_64","entries":[]}`)}
	receipt, e := s.Feature(ctx, state(t, first), r)
	if e != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("software not identity/time bound", e)
	}
	value, e := store.Software(ctx, first.DeviceID)
	if e != nil || value.Data == nil || len(value.Data.Entries) != 0 {
		t.Fatal("empty snapshot lost")
	}
	other, _ := store.Software(ctx, second.DeviceID)
	if other.Data != nil || other.Status != "not_reported" {
		t.Fatal("device isolation failed")
	}
	bad := r
	bad.Data = json.RawMessage(strings.Replace(string(r.Data), `"entries":[]`, `"entries":[],"device_id":"`+second.DeviceID+`"`, 1))
	if _, e = s.Feature(ctx, state(t, first), bad); !errors.Is(e, features.ErrReport) {
		t.Fatal("claimed identity field accepted")
	}
	for _, x := range []struct {
		age    time.Duration
		status string
		stale  bool
	}{{0, "online", false}, {29 * time.Minute, "online", false}, {30 * time.Minute, "online", true}, {-time.Second, "online", true}, {0, "offline", true}, {0, "revoked", true}} {
		view := PresentSoftware(value, View{Status: x.status}, now.Add(x.age))
		if view.Stale != x.stale || !view.HasSnapshot {
			t.Fatal("wrong software freshness")
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		r.Status = status
		r.Data = nil
		if _, e = s.Feature(ctx, state(t, first), r); e != nil {
			t.Fatal(e)
		}
		v, _ := store.Software(ctx, first.DeviceID)
		if !PresentSoftware(v, View{Status: "online"}, *now).Stale || v.Data == nil {
			t.Fatal("failure hid stale software")
		}
	}
	if e = store.RevokeDevice(ctx, first.DeviceID, *now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Feature(ctx, state(t, first), r); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked software accepted")
	}
}
