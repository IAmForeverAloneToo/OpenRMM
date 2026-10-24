package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type DiskSpace struct {
	Capability protocol.Capability `json:"capability"`
	Status     string              `json:"status"`
	ReportedAt int64               `json:"reported_at"`
	SnapshotAt *int64              `json:"snapshot_at"`
	Data       *protocol.DiskSpace `json:"data"`
}

type DeviceWithDiskSpace struct {
	Device
	DiskSpace DiskSpace
}

// Fetch the bounded fleet and latest disk state together so warning freshness
// uses one database snapshot without one extra query per listed device.
func (s *Store) DevicesWithDiskSpace(ctx context.Context) ([]DeviceWithDiskSpace, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id,d.hostname,d.os,d.architecture,d.enrolled_at,d.revoked_at,d.last_contact_at,d.agent_version,
        COALESCE(s.capability_version,0),COALESCE(s.last_status,'not_reported'),COALESCE(s.reported_at,0),COALESCE(s.snapshot_json,''),s.snapshot_at
        FROM devices d LEFT JOIN device_disk_space s ON s.device_id=d.id ORDER BY (d.revoked_at IS NOT NULL),d.enrolled_at DESC,d.id LIMIT 1000`)
	if err != nil {
		return nil, errors.New("cannot list devices with disk space")
	}
	defer rows.Close()
	list := make([]DeviceWithDiskSpace, 0)
	for rows.Next() {
		var item DeviceWithDiskSpace
		item.DiskSpace.Capability.Name = "disk_space"
		var data string
		if err := rows.Scan(&item.ID, &item.Hostname, &item.OS, &item.Architecture, &item.EnrolledAt, &item.RevokedAt, &item.LastContactAt, &item.AgentVersion,
			&item.DiskSpace.Capability.Version, &item.DiskSpace.Status, &item.DiskSpace.ReportedAt, &data, &item.DiskSpace.SnapshotAt); err != nil {
			return nil, errors.New("cannot decode device disk space list")
		}
		if data != "" {
			item.DiskSpace.Data = new(protocol.DiskSpace)
			if json.Unmarshal([]byte(data), item.DiskSpace.Data) != nil {
				return nil, errors.New("cannot decode device disk space")
			}
		}
		list = append(list, item)
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read complete device disk space list")
	}
	return list, nil
}

// Authorization is repeated atomically at the write. Failed/disabled/unsupported
// reports retain the last successful snapshot, so its stale state stays visible.
func (s *Store) RecordDiskSpace(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO device_disk_space(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
        SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL
        AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
        ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,
        reported_at=MAX(device_disk_space.reported_at,excluded.reported_at),
        snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_disk_space.snapshot_json END,
        snapshot_at=CASE WHEN excluded.last_status='ok' THEN MAX(COALESCE(device_disk_space.snapshot_at,0),excluded.snapshot_at) ELSE device_disk_space.snapshot_at END`,
		report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix())
	if err != nil {
		return errors.New("cannot record device disk space")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	status := report.Status
	if report.Capability.Version != 1 {
		status = "unsupported"
	}
	if err = captureAlert(ctx, tx, id, "disk_space", status, report.Data, now); err != nil {
		return err
	}
	if err = captureMetric(ctx, tx, id, "disk_space", status, report.Data, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DiskSpace(ctx context.Context, id string) (DiskSpace, error) {
	value := DiskSpace{Capability: protocol.Capability{Name: "disk_space"}, Status: "not_reported"}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_disk_space WHERE device_id=?`, id).Scan(&value.Capability.Version, &value.Status, &value.ReportedAt, &data, &value.SnapshotAt)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, errors.New("cannot read device disk space")
	}
	if data != "" {
		value.Data = new(protocol.DiskSpace)
		if json.Unmarshal([]byte(data), value.Data) != nil {
			return value, errors.New("cannot decode device disk space")
		}
	}
	return value, nil
}
