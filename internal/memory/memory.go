// Package memory reports physical RAM through an OS collector boundary.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "memory", Version: 1}

const Interval = time.Minute

type Collector interface {
	Collect(context.Context) (protocol.Memory, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	value, err := m.Collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if !Valid(value) {
		return nil, errors.New("memory collector returned invalid data")
	}
	return json.Marshal(value)
}

func Valid(v protocol.Memory) bool {
	return v.TotalBytes > 0 && v.TotalBytes <= 1<<53-1 && v.AvailableBytes <= v.TotalBytes
}

func Normalize(report protocol.FeatureReport) (protocol.FeatureReport, error) {
	if report.Capability.Name != Capability.Name || report.Capability.Version < 1 || report.Capability.Version > 999 {
		return report, features.ErrReport
	}
	switch report.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return report, features.ErrReport
	}
	if report.Capability.Version != Capability.Version {
		report.Status, report.Data = "unsupported", nil
		return report, nil
	}
	if report.Status != "ok" {
		if len(report.Data) != 0 {
			return report, features.ErrReport
		}
		return report, nil
	}
	var input struct {
		Total     *uint64 `json:"total_bytes"`
		Available *uint64 `json:"available_bytes"`
	}
	decoder := json.NewDecoder(bytes.NewReader(report.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || input.Total == nil || input.Available == nil {
		return report, features.ErrReport
	}
	value := protocol.Memory{TotalBytes: *input.Total, AvailableBytes: *input.Available}
	if !Valid(value) {
		return report, features.ErrReport
	}
	report.Data, _ = json.Marshal(value)
	return report, nil
}
