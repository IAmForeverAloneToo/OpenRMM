package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type Processes struct {
	Capability protocol.Capability `json:"capability"`
	Status     string              `json:"status"`
	ReportedAt int64               `json:"reported_at"`
	SnapshotAt *int64              `json:"snapshot_at"`
	Data       *protocol.Processes `json:"data"`
}

// Authorization is repeated atomically at the write. Failed/disabled/unsupported
// reports retain the last successful snapshot, so its stale state stays visible.
func (s *Store) RecordProcesses(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	var err error
	report, err = processes.Normalize(report)
	if err != nil {
		return err
	}
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO device_processes(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
        SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL
        AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
        ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,
        reported_at=MAX(device_processes.reported_at,excluded.reported_at),
        snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_processes.snapshot_json END,
        snapshot_at=CASE WHEN excluded.last_status='ok' THEN MAX(COALESCE(device_processes.snapshot_at,0),excluded.snapshot_at) ELSE device_processes.snapshot_at END WHERE excluded.reported_at>=device_processes.reported_at`,
		report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix())
	if err != nil {
		return errors.New("cannot record device processes")
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		var valid string
		err = s.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&valid)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthentication
		}
		return err
	}
	if count != 1 {
		return ErrAuthentication
	}
	return nil
}

func (s *Store) Processes(ctx context.Context, id string) (Processes, error) {
	value := Processes{Capability: protocol.Capability{Name: "processes"}, Status: "not_reported"}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_processes WHERE device_id=?`, id).Scan(&value.Capability.Version, &value.Status, &value.ReportedAt, &data, &value.SnapshotAt)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, errors.New("cannot read device processes")
	}
	if data != "" {
		value.Data = new(protocol.Processes)
		if json.Unmarshal([]byte(data), value.Data) != nil || !processes.Valid(*value.Data) {
			return value, errors.New("cannot decode device processes")
		}
	}
	return value, nil
}
