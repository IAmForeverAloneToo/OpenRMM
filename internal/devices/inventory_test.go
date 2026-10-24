package devices

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/inventory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func TestInventoryUsesAuthenticatedDeviceAndServerTime(t *testing.T) {
	s, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := s.NewToken(ctx)
	first, err := s.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ = s.NewToken(ctx)
	second, err := s.Enroll(ctx, request(t, token), "peer")
	if err != nil {
		t.Fatal(err)
	}
	report := protocol.FeatureReport{Capability: inventory.Capability, Status: "ok", Data: json.RawMessage(`{"hostname":"test","os":"windows","os_version":"10.0","os_build":19045,"architecture":"amd64","agent_version":"test"}`)}
	receipt, err := s.Feature(ctx, state(t, first), report)
	if err != nil || receipt.DeviceID != first.DeviceID || receipt.ReceivedAt != now.Unix() {
		t.Fatal("inventory identity/time were not server-bound")
	}
	got, err := store.Inventory(ctx, second.DeviceID)
	if err != nil || got.Status != "not_reported" || got.Data != nil {
		t.Fatal("another device updated")
	}
}

func TestInventoryStalenessAndFailureStates(t *testing.T) {
	now := time.Unix(1800000000, 0)
	stamp := now.Unix()
	value := storage.Inventory{Status: "ok", SnapshotAt: &stamp, Data: &protocol.Inventory{Hostname: "retained"}}
	for _, test := range []struct {
		age   time.Duration
		stale bool
	}{{0, false}, {29 * time.Minute, false}, {30 * time.Minute, true}, {-time.Second, true}} {
		if got := PresentInventory(value, View{Status: "online"}, now.Add(test.age)); got.Stale != test.stale {
			t.Fatal("incorrect inventory age boundary")
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		value.Status = status
		if got := PresentInventory(value, View{Status: "online"}, now); !got.Stale || got.Data == nil {
			t.Fatal("failure did not retain stale snapshot")
		}
	}
	value.Status = "ok"
	if !PresentInventory(value, View{Status: "offline"}, now).Stale {
		t.Fatal("offline device snapshot shown as current")
	}
}
