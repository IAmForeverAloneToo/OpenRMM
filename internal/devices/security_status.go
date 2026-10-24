package devices

import (
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/securitystatus"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// SecurityStatusView is the BitLocker and Defender status with
// its freshness and the summaries the device list shows.
type SecurityStatusView struct {
	Capability protocol.Capability      `json:"capability"`
	Status     string                   `json:"status"`
	ReportedAt int64                    `json:"reported_at"`
	SnapshotAt *int64                   `json:"snapshot_at"`
	Data       *protocol.SecurityStatus `json:"data"`
	BitLocker  string                   `json:"bitlocker"`
	Defender   string                   `json:"defender"`
	Stale      bool                     `json:"stale"`
}

func PresentSecurityStatus(value storage.SecurityStatus, device View, now time.Time) SecurityStatusView {
	v := SecurityStatusView{Capability: value.Capability, Status: value.Status, ReportedAt: value.ReportedAt, SnapshotAt: value.SnapshotAt, BitLocker: "unknown", Defender: "unknown", Stale: true}
	if value.Data != nil && securitystatus.Valid(*value.Data) {
		v.Data = value.Data
		v.BitLocker, v.Defender = securitystatus.Summary(*value.Data)
		if value.SnapshotAt != nil {
			v.Stale = value.Status != "ok" || device.Status != "online" || securityAged(*value.SnapshotAt, now)
		}
	}
	return v
}

// securityAged is a snapshot older than two collection intervals.
func securityAged(at int64, now time.Time) bool {
	age := now.Sub(time.Unix(at, 0))
	return age < 0 || age >= 2*securitystatus.Interval
}
