package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type Memory struct {
	Capability protocol.Capability `json:"capability"`
	Status     string              `json:"status"`
	ReportedAt int64               `json:"reported_at"`
	SnapshotAt *int64              `json:"snapshot_at"`
	Data       *protocol.Memory    `json:"data"`
}

// Authorization is repeated atomically at the write. Failed/disabled/unsupported
// reports retain the last successful snapshot, so its stale state stays visible.
func (s *Store) RecordMemory(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO device_memory(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
        SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL
        AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
        ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,
        reported_at=MAX(device_memory.reported_at,excluded.reported_at),
        snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_memory.snapshot_json END,
        snapshot_at=CASE WHEN excluded.last_status='ok' THEN MAX(COALESCE(device_memory.snapshot_at,0),excluded.snapshot_at) ELSE device_memory.snapshot_at END`,
		report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix())
	if err != nil {
		return errors.New("cannot record device memory")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	status := report.Status
	if report.Capability.Version != 1 {
		status = "unsupported"
	}
	if err = captureAlert(ctx, tx, id, "memory", status, report.Data, now); err != nil {
		return err
	}
	if err = captureMetric(ctx, tx, id, "memory", status, report.Data, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Memory(ctx context.Context, id string) (Memory, error) {
	value := Memory{Capability: protocol.Capability{Name: "memory"}, Status: "not_reported"}
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_memory WHERE device_id=?`, id).Scan(&value.Capability.Version, &value.Status, &value.ReportedAt, &data, &value.SnapshotAt)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, errors.New("cannot read device memory")
	}
	if data != "" {
		value.Data = new(protocol.Memory)
		if json.Unmarshal([]byte(data), value.Data) != nil {
			return value, errors.New("cannot decode device memory")
		}
	}
	return value, nil
}
