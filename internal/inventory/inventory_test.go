package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type fakeCollector struct{ err error }

func (c fakeCollector) Collect(context.Context) (protocol.Inventory, error) {
	return protocol.Inventory{Hostname: "fake Windows", OS: "windows", OSVersion: "10.0", OSBuild: 19045, Architecture: "amd64", AgentVersion: "test"}, c.err
}

func TestOSAdapterAndStrictSchema(t *testing.T) {
	module := Module{Collector: fakeCollector{}}
	data, err := module.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	report := protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data}
	if _, err = Normalize(report); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{}`, `null`, `{"hostname":"test","os":"windows","os_version":"10.0","os_build":19045,"architecture":"amd64","agent_version":"test","username":"forbidden"}`} {
		report.Data = json.RawMessage(body)
		if _, err = Normalize(report); err == nil {
			t.Fatal("invalid or extra inventory fields accepted")
		}
	}
	report = protocol.FeatureReport{Capability: protocol.Capability{Name: "inventory", Version: 2}, Status: "ok", Data: data}
	if value, err := Normalize(report); err != nil || value.Status != "unsupported" || len(value.Data) != 0 {
		t.Fatal("newer schema not explicitly unsupported")
	}
	if _, err = (Module{Collector: fakeCollector{err: errors.New("collector unavailable")}}).Collect(context.Background()); err == nil {
		t.Fatal("adapter failure lost")
	}
}
