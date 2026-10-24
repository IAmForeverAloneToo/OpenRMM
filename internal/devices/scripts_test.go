package devices

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"testing"
)

func TestScriptSupportDeviceBindingAndRevocation(t *testing.T) {
	s, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := s.NewToken(ctx)
	credential, e := s.Enroll(ctx, request(t, token), "peer")
	if e != nil {
		t.Fatal(e)
	}
	data, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "disabled"})
	report := protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: data}
	receipt, e := s.Feature(ctx, state(t, credential), report)
	if e != nil || receipt.DeviceID != credential.DeviceID {
		t.Fatal("support identity", e)
	}
	value, e := store.ScriptSupport(ctx, credential.DeviceID)
	if e != nil || value.Status != "ok" || value.ReportedAt != now.Unix() {
		t.Fatal("receipt time", e)
	}
	if e = store.RevokeDevice(ctx, credential.DeviceID, *now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PollScriptRun(ctx, state(t, credential)); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked poll")
	}
	if _, e = s.Feature(ctx, state(t, credential), report); !errors.Is(e, storage.ErrAuthentication) {
		t.Fatal("revoked support")
	}
}
