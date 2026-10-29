package devices

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/inventory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/localaccounts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/logons"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/securitystatus"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sessions"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
)

func (s *Service) Feature(ctx context.Context, state *tls.ConnectionState, report protocol.FeatureReport) (protocol.HeartbeatReceipt, error) {
	d, err := s.Authenticate(ctx, state)
	if err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	if !s.reportAllowed(d.ID) {
		return protocol.HeartbeatReceipt{}, ErrReportsLimited
	}
	switch report.Capability.Name {
	case agentupdate.Capability.Name:
		report, err = agentupdate.Normalize(report)
	case filetransfer.Capability.Name:
		report, err = filetransfer.Normalize(report)
	case scripting.Capability.Name:
		report, err = scripting.Normalize(report)
	case processes.Capability.Name:
		report, err = processes.Normalize(report)
	case software.Capability.Name:
		report, err = software.Normalize(report)
	case sessions.Capability.Name:
		report, err = sessions.Normalize(report)
	case localaccounts.Capability.Name:
		report, err = localaccounts.Normalize(report)
	case sysinfo.Capability.Name:
		report, err = sysinfo.Normalize(report)
	case securitystatus.Capability.Name:
		report, err = securitystatus.Normalize(report)
	case logons.Capability.Name:
		report, err = logons.Normalize(report)
	case windowsupdate.Capability.Name:
		report, err = windowsupdate.Normalize(report)
	case eventlogs.Capability.Name:
		report, err = eventlogs.Normalize(report)
	case inventory.Capability.Name:
		report, err = inventory.Normalize(report)
	case diskspace.Capability.Name:
		report, err = diskspace.Normalize(report)
	case memory.Capability.Name:
		report, err = memory.Normalize(report)
	case cpu.Capability.Name:
		report, err = cpu.Normalize(report)
	case winservices.Capability.Name:
		report, err = winservices.Normalize(report)
	case uptime.Capability.Name:
		report, err = uptime.Normalize(report)
	default:
		return protocol.HeartbeatReceipt{}, features.ErrReport
	}
	if err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	now := s.now()
	fingerprint := deviceidentity.Fingerprint(state.PeerCertificates[0].Raw)
	switch report.Capability.Name {
	case agentupdate.Capability.Name:
		err = s.store.RecordAgentUpgradeSupport(ctx, d.ID, fingerprint, report, now)
	case filetransfer.Capability.Name:
		err = s.store.RecordFileSupport(ctx, d.ID, fingerprint, report, now)
	case scripting.Capability.Name:
		err = s.store.RecordScriptSupport(ctx, d.ID, fingerprint, report, now)
	case processes.Capability.Name:
		err = s.store.RecordProcesses(ctx, d.ID, fingerprint, report, now)
	case software.Capability.Name:
		err = s.store.RecordSoftware(ctx, d.ID, fingerprint, report, now)
	case sessions.Capability.Name:
		err = s.store.RecordSessions(ctx, d.ID, fingerprint, report, now)
	case localaccounts.Capability.Name:
		err = s.store.RecordLocalAccounts(ctx, d.ID, fingerprint, report, now)
	case sysinfo.Capability.Name:
		err = s.store.RecordSystemInfo(ctx, d.ID, fingerprint, report, now)
	case securitystatus.Capability.Name:
		err = s.store.RecordSecurityStatus(ctx, d.ID, fingerprint, report, now)
	case logons.Capability.Name:
		err = s.store.RecordLogons(ctx, d.ID, fingerprint, report, now)
	case windowsupdate.Capability.Name:
		err = s.store.RecordUpdateSupport(ctx, d.ID, fingerprint, report, now)
	case eventlogs.Capability.Name:
		err = s.store.RecordEventLogs(ctx, d.ID, fingerprint, report, now)
	case diskspace.Capability.Name:
		err = s.store.RecordDiskSpace(ctx, d.ID, fingerprint, report, now)
	case memory.Capability.Name:
		err = s.store.RecordMemory(ctx, d.ID, fingerprint, report, now)
	case cpu.Capability.Name:
		err = s.store.RecordCPU(ctx, d.ID, fingerprint, report, now)
	case winservices.Capability.Name:
		err = s.store.RecordServices(ctx, d.ID, fingerprint, report, now)
	case uptime.Capability.Name:
		err = s.store.RecordUptime(ctx, d.ID, fingerprint, report, now)
	default:
		err = s.store.RecordInventory(ctx, d.ID, fingerprint, report, now)
	}
	if err != nil {
		return protocol.HeartbeatReceipt{}, err
	}
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, nil
}

type InventoryView struct {
	storage.Inventory
	Stale       bool   `json:"stale"`
	StatusLabel string `json:"-"`
	LastReport  string `json:"-"`
	LastSuccess string `json:"-"`
}

func PresentInventory(value storage.Inventory, device View, now time.Time) InventoryView {
	v := InventoryView{Inventory: value, Stale: true, LastReport: "Never", LastSuccess: "Never"}
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
		v.Stale = value.Status != "ok" || device.Status != "online" || age < 0 || age >= 30*time.Minute
	}
	return v
}
