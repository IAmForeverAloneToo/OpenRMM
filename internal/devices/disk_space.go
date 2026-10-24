package devices

import (
	"fmt"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

type DiskSpaceView struct {
	storage.DiskSpace
	Stale          bool     `json:"stale"`
	UsedPercent    *float64 `json:"used_percent"`
	StatusLabel    string   `json:"-"`
	LastReport     string   `json:"-"`
	LastSuccess    string   `json:"-"`
	TotalSpace     string   `json:"-"`
	AvailableSpace string   `json:"-"`
	Usage          string   `json:"-"`
	Warning        string   `json:"warning"`
	WarningLabel   string   `json:"-"`
}

func PresentDiskSpace(value storage.DiskSpace, device View, now time.Time) DiskSpaceView {
	// Disk readings expire after two missed five-minute collection intervals.
	v := DiskSpaceView{DiskSpace: value, Stale: true, LastReport: "Never", LastSuccess: "Never", Warning: "unknown", WarningLabel: "Disk status unknown"}
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
		v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 10*time.Minute
	}
	if value.Data != nil && diskspace.Valid(*value.Data) {
		used := 100 * (1 - float64(value.Data.AvailableBytes)/float64(value.Data.TotalBytes))
		v.UsedPercent = &used
		v.Usage = fmt.Sprintf("%.1f%%", used)
		v.TotalSpace = formatBytes(value.Data.TotalBytes)
		v.AvailableSpace = formatBytes(value.Data.AvailableBytes)
		if !v.Stale {
			v.Warning, v.WarningLabel = "ok", "Disk space OK"
			// Valid limits totals to 2^53-1, so this integer comparison cannot
			// overflow and avoids rounding a reading across the 10% boundary.
			if value.Data.AvailableBytes*10 < value.Data.TotalBytes {
				v.Warning, v.WarningLabel = "low", "Low disk space"
			}
		}
	} else {
		v.Stale = true
	}
	return v
}

func formatBytes(value uint64) string {
	for _, unit := range []struct {
		size  uint64
		label string
	}{
		{1 << 50, "PiB"}, {1 << 40, "TiB"}, {1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"},
	} {
		if value >= unit.size {
			return fmt.Sprintf("%.1f %s", float64(value)/float64(unit.size), unit.label)
		}
	}
	return fmt.Sprintf("%d B", value)
}
