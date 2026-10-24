package winservices

import (
	"context"
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
)

func TestStrictServiceSnapshots(t *testing.T) {
	valid := `{"items":[{"name":"Example","display_name":"Example service","state":"stopped","can_start":true,"can_stop":false}],"visibility":"queryable_services_only"}`
	for _, s := range []string{valid, `{"items":[],"visibility":"queryable_services_only"}`} {
		if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(s)}); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{`null`, `{}`, `{"items":null,"visibility":"queryable_services_only"}`, `{"items":[],"visibility":"all"}`, `{"items":[],"visibility":"queryable_services_only","device_id":"x"}`, `{"items":[{"name":"x","display_name":"x","state":"running","can_start":true}],"visibility":"queryable_services_only"}`, `{"items":[{"name":"OpenRMMAgent","display_name":"agent","state":"running","can_start":true,"can_stop":true}],"visibility":"queryable_services_only"}`} {
		if _, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(s)}); e == nil {
			t.Fatal("invalid snapshot accepted", s)
		}
	}
	v := protocol.Services{Visibility: "queryable_services_only", Items: []protocol.WindowsService{{Name: "x", DisplayName: "x", State: "running"}, {Name: "X", DisplayName: "x", State: "running"}}}
	if Valid(v) {
		t.Fatal("case-insensitive duplicate accepted")
	}
}
func FuzzNormalizeServices(f *testing.F) {
	f.Add([]byte(`{"items":[],"visibility":"queryable_services_only"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, e := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data})
		if e == nil {
			var v protocol.Services
			if json.Unmarshal(r.Data, &v) != nil || !Valid(v) {
				t.Fatal("invalid normalized data")
			}
		}
	})
}
func TestUnknownServiceIsNotFound(t *testing.T) {
	r := NewAdapter().Execute(context.Background(), protocol.ServiceAction{ID: "0123456789abcdef0123456789abcdef", Service: "OpenRMMNoSuchServiceFixture", Action: "stop"})
	if r.Outcome != "not_found" && r.Outcome != "denied" {
		t.Fatal("unexpected outcome", r.Outcome)
	}
}
func TestEveryOpenRMMServiceProtected(t *testing.T) {
	for _, name := range []string{"OpenRMMAgent", "openrmmagent"} {
		if Manageable(name) {
			t.Fatal("OpenRMM service manageable", name)
		}
		r := NewAdapter().Execute(context.Background(), protocol.ServiceAction{ID: "0123456789abcdef0123456789abcdef", Service: name, Action: "stop"})
		if r.Outcome != "denied" {
			t.Fatal("OpenRMM service controlled", name)
		}
	}
	if !Manageable("Spooler") {
		t.Fatal("ordinary service refused")
	}
}
