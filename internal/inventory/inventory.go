// Package inventory implements the first feature through an OS collector boundary.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "inventory", Version: 1}
var ErrReport = features.ErrReport

type Collector interface {
	Collect(context.Context) (protocol.Inventory, error)
}

type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	value, err := m.Collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if !Valid(value) {
		return nil, errors.New("inventory collector returned invalid metadata")
	}
	return json.Marshal(value)
}

func Valid(v protocol.Inventory) bool {
	base := protocol.Heartbeat{Hostname: v.Hostname, OS: v.OS, Architecture: v.Architecture, AgentVersion: v.AgentVersion}
	parts := strings.Split(v.OSVersion, ".")
	if !base.Valid() || len(parts) != 2 || len(v.OSVersion) > 16 || v.OSBuild == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 16); err != nil {
			return false
		}
	}
	return true
}

// Normalize validates the known v1 schema. A newer inventory version is recorded
// explicitly as unsupported without interpreting or persisting its payload.
func Normalize(report protocol.FeatureReport) (protocol.FeatureReport, error) {
	if report.Capability.Name != Capability.Name || report.Capability.Version < 1 || report.Capability.Version > 999 {
		return report, ErrReport
	}
	if report.Status != "ok" && report.Status != "failed" && report.Status != "disabled" && report.Status != "unsupported" {
		return report, ErrReport
	}
	if report.Capability.Version != Capability.Version {
		report.Status, report.Data = "unsupported", nil
		return report, nil
	}
	if report.Status != "ok" {
		if len(report.Data) != 0 {
			return report, ErrReport
		}
		return report, nil
	}
	var value protocol.Inventory
	decoder := json.NewDecoder(bytes.NewReader(report.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || !Valid(value) {
		return report, ErrReport
	}
	report.Data, _ = json.Marshal(value)
	return report, nil
}
