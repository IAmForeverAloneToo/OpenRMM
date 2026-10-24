package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/inventory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
)

func FuzzFeatureJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"capability":{"name":"services","version":1},"status":"ok","data":{"items":[],"visibility":"queryable_services_only"}}`),
		[]byte(`{"capability":{"name":"inventory","version":1},"status":"disabled"}`),
		[]byte(`{"capability":{"name":"inventory","version":2},"status":"ok","data":{"future":true}}`),
		[]byte(`{"device_id":"ffffffffffffffffffffffffffffffff"}`),
		[]byte(`{"capability":{"name":"inventory","version":1},"status":"ok","data":null}`),
		[]byte(`{"capability":{"name":"disk_space","version":1},"status":"ok","data":{"drive":"C:\\","total_bytes":100,"available_bytes":0}}`),
		[]byte(`{"capability":{"name":"disk_space","version":1},"status":"ok","data":{"drive":"C:\\","total_bytes":100}}`),
		[]byte(`{"capability":{"name":"disk_space","version":2},"status":"ok","data":{"future":true}}`),
		[]byte(`null`), []byte(`{} {}`), bytes.Repeat([]byte("x"), 8193),
		[]byte(`{"capability":{"name":"uptime","version":1},"status":"ok","data":{"uptime_seconds":0,"estimated_boot_at":1800000000}}`),
		[]byte(`{"capability":{"name":"uptime","version":1},"status":"ok","data":{"uptime_seconds":1}}`),
		[]byte(`{"capability":{"name":"uptime","version":2},"status":"ok","data":{"future":true}}`),
		[]byte(`{"capability":{"name":"cpu","version":1},"status":"ok","data":{"usage_percent":0,"sample_ms":1000}}`),
		[]byte(`{"capability":{"name":"cpu","version":1},"status":"ok","data":{"sample_ms":1000}}`),
		[]byte(`{"capability":{"name":"cpu","version":2},"status":"ok","data":{"future":true}}`),
		[]byte(`{"capability":{"name":"memory","version":1},"status":"ok","data":{"total_bytes":100,"available_bytes":0}}`),
		[]byte(`{"capability":{"name":"memory","version":1},"status":"ok","data":{"total_bytes":100}}`),
		[]byte(`{"capability":{"name":"memory","version":2},"status":"ok","data":{"future":true}}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		request := httptest.NewRequest("POST", "https://localhost/api/v1/agent/features", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		var report protocol.FeatureReport
		if !readJSON(response, request, &report) {
			if response.Code != 400 && response.Code != 413 {
				t.Fatal("malformed input produced an unexpected response")
			}
			return
		}
		if len(body) > 8192 {
			t.Fatal("oversized request accepted")
		}
		if report.Capability.Name == "services" {
			r, e := winservices.Normalize(report)
			if e == nil && r.Status == "ok" {
				var v protocol.Services
				if json.Unmarshal(r.Data, &v) != nil || !winservices.Valid(v) {
					t.Fatal("invalid services accepted")
				}
			}
			return
		}
		if report.Capability.Name == "disk_space" {
			normalized, err := diskspace.Normalize(report)
			if err != nil {
				return
			}
			if normalized.Status == "ok" {
				var value protocol.DiskSpace
				if json.Unmarshal(normalized.Data, &value) != nil || !diskspace.Valid(value) {
					t.Fatal("invalid disk reading accepted")
				}
			} else if len(normalized.Data) != 0 {
				t.Fatal("failed or unsupported disk payload retained")
			}
			return
		}
		if report.Capability.Name == "uptime" {
			normalized, err := uptime.Normalize(report)
			if err != nil {
				return
			}
			if normalized.Status == "ok" {
				var value protocol.Uptime
				if json.Unmarshal(normalized.Data, &value) != nil || !uptime.Valid(value) {
					t.Fatal("invalid uptime accepted")
				}
			} else if len(normalized.Data) != 0 {
				t.Fatal("non-success uptime data retained")
			}
			return
		}
		if report.Capability.Name == "cpu" {
			normalized, err := cpu.Normalize(report)
			if err != nil {
				return
			}
			if normalized.Status == "ok" {
				var value protocol.CPU
				if json.Unmarshal(normalized.Data, &value) != nil || !cpu.Valid(value) {
					t.Fatal("invalid CPU accepted")
				}
			} else if len(normalized.Data) != 0 {
				t.Fatal("non-success CPU data retained")
			}
			return
		}
		if report.Capability.Name == "memory" {
			normalized, err := memory.Normalize(report)
			if err != nil {
				return
			}
			if normalized.Status == "ok" {
				var value protocol.Memory
				if json.Unmarshal(normalized.Data, &value) != nil || !memory.Valid(value) {
					t.Fatal("invalid RAM reading accepted")
				}
			} else if len(normalized.Data) != 0 {
				t.Fatal("non-success RAM payload retained")
			}
			return
		}
		normalized, err := inventory.Normalize(report)
		if err != nil {
			return
		}
		if normalized.Capability.Name != "inventory" || normalized.Capability.Version < 1 || normalized.Capability.Version > 999 {
			t.Fatal("unknown capability accepted")
		}
		if normalized.Status != "ok" && len(normalized.Data) != 0 {
			t.Fatal("unsuccessful or unsupported payload retained")
		}
		if normalized.Status == "ok" {
			var value protocol.Inventory
			if json.Unmarshal(normalized.Data, &value) != nil || !inventory.Valid(value) {
				t.Fatal("invalid snapshot accepted")
			}
		}
	})
}
