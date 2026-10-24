package storage

import (
	"context"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

// Agent fleet status compares every active Windows device with the newest
// usable release (highest sequence, not withdrawn, not expired).
const (
	FleetUpToDate   = "up_to_date"   // runs the latest release
	FleetUpdating   = "updating"     // an update job is queued or in progress
	FleetAvailable  = "available"    // can be updated now
	FleetOffline    = "offline"      // not reporting; checked again when back
	FleetNeedsLocal = "needs_local"  // updater missing, off, untrusted key or needs recovery
	FleetNoRelease  = "no_release"   // no usable release in the library
	FleetUnknown    = "not_reported" // no updater report yet
)

type AgentFleetDevice struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	GroupID     string `json:"group_id"`
	Version     string `json:"agent_version"`
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	CurrentHash string `json:"current_sha256"`
	HighWater   int64  `json:"high_water"`
	Job         string `json:"job_status"`
	// Reinstall lists local helpers older than this server's release; they are
	// replaced only by a local administrator reinstall.
	Reinstall []string `json:"reinstall"`
}

type AgentFleet struct {
	Latest  *AgentRelease      `json:"latest"`
	Devices []AgentFleetDevice `json:"devices"`
}

// LatestAgentRelease returns the newest usable release, or nil.
func (s *Store) LatestAgentRelease(ctx context.Context, now time.Time) (*AgentRelease, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT "+agentReleaseColumns+" FROM agent_releases WHERE withdrawn=0 ORDER BY sequence DESC LIMIT 16")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		r, e := scanAgentRelease(rows)
		if e != nil {
			return nil, e
		}
		if agentupdate.Fresh(r.Release.Manifest, now) {
			return &r, nil
		}
	}
	return nil, rows.Err()
}

func (s *Store) AgentFleet(ctx context.Context, now time.Time, offline time.Duration) (AgentFleet, error) {
	latest, e := s.LatestAgentRelease(ctx, now)
	if e != nil {
		return AgentFleet{}, e
	}
	rows, e := s.db.QueryContext(ctx, `SELECT d.id,d.hostname,COALESCE(o.group_id,''),d.agent_version,COALESCE(d.last_contact_at,0),
 COALESCE(s.last_status,''),COALESCE(s.reported_at,0),COALESCE(s.support_json,''),
 COALESCE((SELECT j.status FROM agent_upgrade_jobs j WHERE j.device_id=d.id ORDER BY j.created_at DESC,j.id LIMIT 1),''),
 COALESCE(f.last_status,''),COALESCE(f.support_json,'')
 FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id LEFT JOIN device_agent_upgrade_support s ON s.device_id=d.id LEFT JOIN device_script_support f ON f.device_id=d.id
 WHERE d.revoked_at IS NULL AND d.os='windows' AND d.architecture='amd64' ORDER BY d.hostname,d.id LIMIT 1000`)
	if e != nil {
		return AgentFleet{}, e
	}
	defer rows.Close()
	out := AgentFleet{Latest: latest, Devices: []AgentFleetDevice{}}
	for rows.Next() {
		var d AgentFleetDevice
		var contact, reported int64
		var reportStatus, raw, scriptStatus, scriptRaw string
		if e = rows.Scan(&d.ID, &d.Hostname, &d.GroupID, &d.Version, &contact, &reportStatus, &reported, &raw, &d.Job, &scriptStatus, &scriptRaw); e != nil {
			return AgentFleet{}, e
		}
		var support protocol.AgentUpgradeSupport
		valid := reportStatus == "ok" && agentupdate.Decode([]byte(raw), &support) == nil && agentupdate.SupportValid(support)
		if valid {
			d.CurrentHash, d.HighWater = support.CurrentHash, support.HighWater
		}
		online := contact > now.Add(-offline).Unix() && contact <= now.Unix()
		d.Status, d.Reason = fleetStatus(latest, support, valid, reportStatus, online, d.Job)
		d.Reinstall = []string{}
		// Current agents update themselves through MSI packages; an
		// agent that still relies on the separate updater needs the MSI once.
		if valid && support.Installer != "msi" {
			d.Reinstall = append(d.Reinstall, "agent MSI")
		}
		var runner protocol.ScriptSupport
		if scriptStatus == "ok" && scripting.Decode([]byte(scriptRaw), &runner) == nil && runner.Administrator != "missing" && runner.Administrator != "unsupported" && runner.RunnerRevision < scripting.RunnerRevision {
			d.Reinstall = append(d.Reinstall, "script runner")
		}
		out.Devices = append(out.Devices, d)
	}
	return out, rows.Err()
}

func fleetStatus(latest *AgentRelease, s protocol.AgentUpgradeSupport, valid bool, reportStatus string, online bool, job string) (string, string) {
	if job == "queued" || job == "dispatched" {
		return FleetUpdating, ""
	}
	if valid && latest != nil && (s.CurrentHash == agentupdate.AgentHash(latest.Release.Manifest) || s.HighWater >= latest.Release.Manifest.Sequence) {
		return FleetUpToDate, ""
	}
	if latest == nil {
		return FleetNoRelease, ""
	}
	if !online {
		return FleetOffline, ""
	}
	switch {
	case reportStatus == "":
		return FleetUnknown, "The agent has not reported its update support yet."
	case reportStatus == "disabled" || reportStatus == "unsupported":
		return FleetNeedsLocal, "The agent's update feature is off or unsupported on this device."
	case !valid:
		return FleetNeedsLocal, "The agent's update report could not be read."
	}
	// MSI releases need an agent that installs them itself.
	switch {
	case agentupdate.MSI(latest.Release.Manifest) && s.Installer != "msi":
		return FleetNeedsLocal, "This agent predates self-update through MSI packages; install the agent MSI on the device once."
	case !agentupdate.MSI(latest.Release.Manifest) && s.Installer == "msi":
		return FleetNeedsLocal, "The latest release is an executable for the earlier updater; publish an MSI release."
	}
	switch s.Broker {
	case "missing":
		return FleetNeedsLocal, "This device's agent has no update support."
	case "disabled":
		return FleetNeedsLocal, "Self-update is unavailable on this device: its agent trusts no signing key or has no rollback package. Install the agent MSI again."
	case "denied":
		return FleetNeedsLocal, "The update engine refused the agent's service configuration."
	case "recovery_required":
		return FleetNeedsLocal, "The agent's update engine needs local recovery."
	case "busy":
		return FleetUpdating, ""
	}
	trusted := false
	for _, k := range s.KeyIDs {
		if k == latest.Release.Manifest.KeyID {
			trusted = true
		}
	}
	if !trusted {
		return FleetNeedsLocal, "This device's agent does not trust the release signing key."
	}
	return FleetAvailable, ""
}
