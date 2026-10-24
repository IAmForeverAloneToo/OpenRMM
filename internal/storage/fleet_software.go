package storage

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
)

const FleetSoftwareDeviceLimit = 1000
const FleetSoftwareByteLimit = 64 * 1024 * 1024
const FleetSoftwareExamples = 5

var ErrFleetSoftware = errors.New("invalid fleet software filters")
var ErrFleetSoftwareLimit = errors.New("fleet software report too large; narrow group or tag")

type FleetSoftwareFilter struct {
	Query     string `json:"q"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	Group     string `json:"group"`
	Tag       string `json:"tag"`
}

func (f FleetSoftwareFilter) Valid() bool {
	tags, e := ParseDeviceTags(f.Tag)
	return software.Text(f.Query, 200, false) && software.Text(f.Version, 256, false) && software.Text(f.Publisher, 512, false) &&
		(f.Group == "" || f.Group == "ungrouped" || ValidOrganizationID(f.Group)) && e == nil &&
		(f.Tag == "" || len(tags) == 1 && tags[0] == f.Tag)
}

// Examples are bounded registration samples, never a replacement snapshot.
type FleetSoftwareDevice struct {
	Device        Device                   `json:"device"`
	GroupID       string                   `json:"group_id"`
	GroupName     string                   `json:"group_name"`
	Tags          []string                 `json:"tags"`
	Capability    protocol.Capability      `json:"capability"`
	Status        string                   `json:"status"`
	ReportedAt    int64                    `json:"reported_at"`
	SnapshotAt    *int64                   `json:"snapshot_at"`
	HasSnapshot   bool                     `json:"has_snapshot"`
	Coverage      string                   `json:"coverage"`
	Registrations int                      `json:"registrations"`
	Matches       int                      `json:"matches"`
	Examples      []protocol.SoftwareEntry `json:"examples"`
}

func fleetSoftwareMatches(x protocol.SoftwareEntry, f FleetSoftwareFilter) bool {
	return (strings.Contains(strings.ToLower(x.Name), f.Query) || strings.Contains(strings.ToLower(x.Version), f.Query) || strings.Contains(strings.ToLower(x.Publisher), f.Query)) &&
		strings.Contains(strings.ToLower(x.Version), f.Version) && strings.Contains(strings.ToLower(x.Publisher), f.Publisher)
}

// Scope, byte/count preflight and snapshot reads share one database transaction.
// No excluded device contributes to limits, counts, examples or group names.
// Decode one snapshot at a time; never retain the entire fleet's raw JSON.
func (s *Store) FleetSoftwareForSession(ctx context.Context, v Session, f FleetSoftwareFilter) ([]FleetSoftwareDevice, error) {
	if !f.Valid() {
		return nil, ErrFleetSoftware
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	scope, args := technicianScope(v, "d.id")
	from := ` FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id LEFT JOIN device_software sw ON sw.device_id=d.id
 WHERE d.revoked_at IS NULL AND (` + scope + `)`
	if f.Group == "ungrouped" {
		from += ` AND o.group_id IS NULL`
	} else if f.Group != "" {
		from += ` AND o.group_id=?`
		args = append(args, f.Group)
	}
	if f.Tag != "" {
		from += ` AND EXISTS(SELECT 1 FROM json_each(COALESCE(o.tags_json,'[]')) WHERE value=?)`
		args = append(args, f.Tag)
	}
	var count, bytes int64
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(LENGTH(CAST(COALESCE(sw.snapshot_json,'') AS BLOB))),0)`+from, args...).Scan(&count, &bytes); e != nil {
		return nil, e
	}
	if count > FleetSoftwareDeviceLimit || bytes > FleetSoftwareByteLimit {
		return nil, ErrFleetSoftwareLimit
	}
	rows, e := tx.QueryContext(ctx, `SELECT d.id,d.hostname,d.os,d.architecture,d.enrolled_at,d.agent_version,d.last_contact_at,COALESCE(o.group_id,''),
 COALESCE((SELECT name FROM device_groups WHERE id=o.group_id),''),COALESCE(o.tags_json,'[]'),
 COALESCE(sw.capability_version,1),COALESCE(sw.last_status,'not_reported'),COALESCE(sw.reported_at,0),sw.snapshot_at,COALESCE(sw.snapshot_json,'')`+from+` LIMIT 1000`, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	f.Query, f.Version, f.Publisher = strings.ToLower(f.Query), strings.ToLower(f.Version), strings.ToLower(f.Publisher)
	out := []FleetSoftwareDevice{}
	for rows.Next() {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		x := FleetSoftwareDevice{Capability: software.Capability, Tags: []string{}, Examples: []protocol.SoftwareEntry{}}
		var raw, tags string
		if e = rows.Scan(&x.Device.ID, &x.Device.Hostname, &x.Device.OS, &x.Device.Architecture, &x.Device.EnrolledAt, &x.Device.AgentVersion, &x.Device.LastContactAt, &x.GroupID, &x.GroupName, &tags,
			&x.Capability.Version, &x.Status, &x.ReportedAt, &x.SnapshotAt, &raw); e != nil {
			return nil, e
		}
		if json.Unmarshal([]byte(tags), &x.Tags) != nil {
			return nil, errors.New("cannot decode software device tags")
		}
		if raw != "" {
			var data protocol.Software
			if len(raw) > software.MaxBytes || json.Unmarshal([]byte(raw), &data) != nil || !software.Valid(data) {
				return nil, errors.New("cannot decode fleet software snapshot")
			}
			x.HasSnapshot, x.Coverage, x.Registrations = true, data.Coverage, len(data.Entries)
			for i, entry := range data.Entries {
				if i%64 == 0 {
					if e = ctx.Err(); e != nil {
						return nil, e
					}
				}
				if fleetSoftwareMatches(entry, f) {
					x.Matches++
					if len(x.Examples) < FleetSoftwareExamples {
						x.Examples = append(x.Examples, entry)
					}
				}
			}
		}
		out = append(out, x)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	// The transactional preflight ensures every selected row fits the limit.
	// Sort only the compact summaries: ordering raw JSON in SQL can spool the
	// entire snapshot set into a temporary sort table before the first read.
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Device.Hostname), strings.ToLower(out[j].Device.Hostname)
		if a != b {
			return a < b
		}
		return out[i].Device.ID < out[j].Device.ID
	})
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return out, nil
}
