package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type UpdateSupport struct {
	Capability protocol.Capability     `json:"capability"`
	Status     string                  `json:"status"`
	ReportedAt int64                   `json:"reported_at"`
	SnapshotAt *int64                  `json:"snapshot_at"`
	Data       *protocol.UpdateSupport `json:"data"`
}

// Authorization is repeated atomically at the write. Failed/disabled/unsupported
// reports retain the last successful snapshot, so its stale state stays visible.
func (s *Store) RecordUpdateSupport(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO device_update_support(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
        SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL
        AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
        ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,
        reported_at=MAX(device_update_support.reported_at,excluded.reported_at),
        snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_update_support.snapshot_json END,
        snapshot_at=CASE WHEN excluded.last_status='ok' THEN MAX(COALESCE(device_update_support.snapshot_at,0),excluded.snapshot_at) ELSE device_update_support.snapshot_at END`,
		report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix())
	if err != nil {
		return errors.New("cannot record device update support")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	return nil
}

func (s *Store) UpdateSupport(ctx context.Context, id string) (UpdateSupport, error) {
	value := UpdateSupport{Capability: protocol.Capability{Name: "windows_updates"}, Status: "not_reported"}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_update_support WHERE device_id=?`, id).Scan(&value.Capability.Version, &value.Status, &value.ReportedAt, &data, &value.SnapshotAt)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, errors.New("cannot read device update support")
	}
	if data != "" {
		value.Data = new(protocol.UpdateSupport)
		if json.Unmarshal([]byte(data), value.Data) != nil {
			return value, errors.New("cannot decode device update support")
		}
	}
	return value, nil
}
