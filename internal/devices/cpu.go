package devices

import (
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"time"
)

type CPUView struct {
	storage.CPU
	Stale          bool   `json:"stale"`
	StatusLabel    string `json:"-"`
	LastReport     string `json:"-"`
	LastSuccess    string `json:"-"`
	Usage          string `json:"-"`
	SampleDuration string `json:"-"`
}

func PresentCPU(value storage.CPU, device View, now time.Time) CPUView {
	v := CPUView{CPU: value, Stale: true, LastReport: "Never", LastSuccess: "Never"}
	switch value.Status {
	case "ok":
		v.StatusLabel = "Collected"
	case "failed":
		v.StatusLabel = "Collection failed"
	case "disabled":
		v.StatusLabel = "Disabled"
	case "unsupported":
		v.StatusLabel = "Unsupported"
	default:
		v.StatusLabel = "Not reported"
	}
	if value.ReportedAt != 0 {
		v.LastReport = time.Unix(value.ReportedAt, 0).UTC().Format(time.RFC3339)
	}
	if value.SnapshotAt != nil {
		stamp := time.Unix(*value.SnapshotAt, 0)
		v.LastSuccess = stamp.UTC().Format(time.RFC3339)
		age := now.Sub(stamp)
		v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 2*time.Minute
	}
	if value.Data != nil && cpu.Valid(*value.Data) {
		v.Usage = fmt.Sprintf("%.1f%%", value.Data.UsagePercent)
		v.SampleDuration = fmt.Sprintf("%.3f seconds", float64(value.Data.SampleMilliseconds)/1000)
	} else {
		v.Stale = true
	}
	return v
}
