// Package uptime reports OS-session elapsed time through an OS adapter.
package uptime

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

var Capability = protocol.Capability{Name: "uptime", Version: 1}

const Interval = time.Minute

// DurationSinceBoot returns time.Duration; reject overflow and bound JSON/date
// arithmetic to that duration's range and UTC years 1970 through 9999.
const MaxUptimeSeconds uint64 = 9223372036
const maxUnix int64 = 253402300799

type Collector interface {
	Collect(context.Context) (protocol.Uptime, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	value, err := m.Collector.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if !Valid(value) {
		return nil, errors.New("uptime collector returned invalid data")
	}
	return json.Marshal(value)
}
func Valid(v protocol.Uptime) bool {
	return v.UptimeSeconds <= MaxUptimeSeconds && v.EstimatedBootAt > 0 && v.EstimatedBootAt <= maxUnix-int64(v.UptimeSeconds)
}
func fromDuration(elapsed time.Duration, now time.Time) (protocol.Uptime, error) {
	if elapsed < 0 {
		return protocol.Uptime{}, errors.New("invalid OS uptime duration")
	}
	value := protocol.Uptime{UptimeSeconds: uint64(elapsed / time.Second), EstimatedBootAt: now.Add(-elapsed).Unix()}
	if !Valid(value) {
		return protocol.Uptime{}, errors.New("invalid uptime or device clock")
	}
	return value, nil
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
		Seconds *uint64 `json:"uptime_seconds"`
		Boot    *int64  `json:"estimated_boot_at"`
	}
	decoder := json.NewDecoder(bytes.NewReader(report.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || input.Seconds == nil || input.Boot == nil {
		return report, features.ErrReport
	}
	value := protocol.Uptime{UptimeSeconds: *input.Seconds, EstimatedBootAt: *input.Boot}
	if !Valid(value) {
		return report, features.ErrReport
	}
	report.Data, _ = json.Marshal(value)
	return report, nil
}
