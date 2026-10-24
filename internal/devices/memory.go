package devices

import (
	"fmt"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

type MemoryView struct {
	storage.Memory
	Stale           bool     `json:"stale"`
	UsedPercent     *float64 `json:"used_percent"`
	StatusLabel     string   `json:"-"`
	LastReport      string   `json:"-"`
	LastSuccess     string   `json:"-"`
	TotalMemory     string   `json:"-"`
	AvailableMemory string   `json:"-"`
	Usage           string   `json:"-"`
}

func PresentMemory(value storage.Memory, device View, now time.Time) MemoryView {
	v := MemoryView{Memory: value, Stale: true, LastReport: "Never", LastSuccess: "Never"}
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
	if value.Data != nil && memory.Valid(*value.Data) {
		used := 100 * (1 - float64(value.Data.AvailableBytes)/float64(value.Data.TotalBytes))
		v.UsedPercent = &used
		v.Usage = fmt.Sprintf("%.1f%%", used)
		v.TotalMemory = formatBytes(value.Data.TotalBytes)
		v.AvailableMemory = formatBytes(value.Data.AvailableBytes)
	} else {
		v.Stale = true
	}
	return v
}
