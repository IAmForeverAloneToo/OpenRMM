package diskspace

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type fakeCollector struct {
	value protocol.DiskSpace
	err   error
}

func (c fakeCollector) Collect(context.Context) (protocol.DiskSpace, error) { return c.value, c.err }

func TestCollectorBoundaryAndStrictReport(t *testing.T) {
	for _, available := range []uint64{0, 25, 100} {
		data, err := (Module{fakeCollector{value: protocol.DiskSpace{Drive: `C:\`, TotalBytes: 100, AvailableBytes: available}}}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{
		`null`, `{}`, `{"drive":"C:\\","total_bytes":100}`, `{"drive":"C:\\","total_bytes":100,"available_bytes":null}`,
		`{"drive":"C:\\","total_bytes":0,"available_bytes":0}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":101}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":-1}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":1.5}`,
		`{"drive":"C:\\","total_bytes":9007199254740992,"available_bytes":0}`,
		`{"drive":"C:\\Windows","total_bytes":100,"available_bytes":20}`,
		`{"drive":"<script>","total_bytes":100,"available_bytes":20}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":20,"device_id":"forged"}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":20,"received_at":1}`,
		`{"drive":"C:\\","total_bytes":100,"available_bytes":20} {}`,
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(body)}); !errors.Is(err, features.ErrReport) {
			t.Fatalf("invalid disk report accepted: %s", body)
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status}); err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status, Data: json.RawMessage(`{}`)}); err == nil {
			t.Fatal("non-success payload accepted")
		}
	}
	for _, cap := range []protocol.Capability{{Name: "disk_space", Version: 0}, {Name: "disk_space", Version: 1000}, {Name: "unknown", Version: 1}} {
		if _, err := Normalize(protocol.FeatureReport{Capability: cap, Status: "ok"}); err == nil {
			t.Fatal("unknown capability accepted")
		}
	}
	newer, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "disk_space", Version: 2}, Status: "ok", Data: json.RawMessage(`{"future":true}`)})
	if err != nil || newer.Status != "unsupported" || len(newer.Data) != 0 {
		t.Fatal("newer schema not discarded")
	}
	if _, err := (Module{fakeCollector{err: errors.New("unavailable")}}).Collect(context.Background()); err == nil {
		t.Fatal("collector error lost")
	}
	if _, err := (Module{fakeCollector{}}).Collect(context.Background()); err == nil {
		t.Fatal("invalid collector result accepted")
	}
}
