package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type fakeCollector struct {
	value protocol.Memory
	err   error
}

func (c fakeCollector) Collect(context.Context) (protocol.Memory, error) { return c.value, c.err }

func TestMemoryAdapterAndStrictSchema(t *testing.T) {
	for _, available := range []uint64{0, 25, 100} {
		data, err := (Module{fakeCollector{value: protocol.Memory{TotalBytes: 100, AvailableBytes: available}}}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{
		`null`, `{}`, `{"total_bytes":100}`, `{"available_bytes":0}`, `{"total_bytes":100,"available_bytes":null}`,
		`{"total_bytes":0,"available_bytes":0}`, `{"total_bytes":100,"available_bytes":101}`, `{"total_bytes":100,"available_bytes":-1}`,
		`{"total_bytes":100,"available_bytes":1.5}`, `{"total_bytes":9007199254740992,"available_bytes":0}`,
		`{"total_bytes":100,"available_bytes":25,"processes":[]}`, `{"total_bytes":100,"available_bytes":25,"device_id":"forged"}`,
		`{"total_bytes":100,"available_bytes":25,"received_at":1}`, `{"total_bytes":100,"available_bytes":25} {}`,
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(body)}); !errors.Is(err, features.ErrReport) {
			t.Fatalf("invalid memory payload accepted: %s", body)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status}); err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status, Data: json.RawMessage(`{}`)}); err == nil {
			t.Fatal("non-success data accepted")
		}
	}
	for _, cap := range []protocol.Capability{{Name: "memory", Version: 0}, {Name: "memory", Version: 1000}, {Name: "unknown", Version: 1}} {
		if _, err := Normalize(protocol.FeatureReport{Capability: cap, Status: "ok"}); err == nil {
			t.Fatal("unknown capability accepted")
		}
	}
	newer, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "memory", Version: 2}, Status: "ok", Data: json.RawMessage(`{"future":true}`)})
	if err != nil || newer.Status != "unsupported" || len(newer.Data) != 0 {
		t.Fatal("newer payload not discarded")
	}
	if _, err := (Module{fakeCollector{err: errors.New("collector unavailable")}}).Collect(context.Background()); err == nil {
		t.Fatal("collector error lost")
	}
	if _, err := (Module{fakeCollector{}}).Collect(context.Background()); err == nil {
		t.Fatal("invalid collector value accepted")
	}
}
