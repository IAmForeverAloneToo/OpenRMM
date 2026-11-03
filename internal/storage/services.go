package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type Services struct {
	Capability protocol.Capability `json:"capability"`
	Status     string              `json:"status"`
	ReportedAt int64               `json:"reported_at"`
	SnapshotAt *int64              `json:"snapshot_at"`
	Data       *protocol.Services  `json:"data"`
}

// Authorization is repeated atomically at the write. Failed/disabled/unsupported
// reports retain the last successful snapshot, so its stale state stays visible.
func (s *Store) RecordServices(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	return s.telemetry(ctx, func(ctx context.Context, tx *telemetryTx) error {
		var err error
		var snapshotAt any
		if report.Status == "ok" {
			snapshotAt = now.Unix()
		}
		// The snapshot time comes back for the stored check results.
		var stored *int64
		err = tx.QueryRowContext(ctx, `INSERT INTO device_services(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
        SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL
        AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
        ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,
        reported_at=MAX(device_services.reported_at,excluded.reported_at),
        snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_services.snapshot_json END,
        snapshot_at=CASE WHEN excluded.last_status='ok' THEN MAX(COALESCE(device_services.snapshot_at,0),excluded.snapshot_at) ELSE device_services.snapshot_at END
        RETURNING snapshot_at`,
			report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix()).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAuthentication
		}
		if err != nil {
			return errors.New("cannot record device services")
		}
		if err = captureHealth(ctx, tx, id, report, stored, now); err != nil {
			return err
		}
		return nil
	})
}

func (s *Store) Services(ctx context.Context, id string) (Services, error) {
	value := Services{Capability: protocol.Capability{Name: "services"}, Status: "not_reported"}
	var data string
	err := s.rdb.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM device_services WHERE device_id=?`, id).Scan(&value.Capability.Version, &value.Status, &value.ReportedAt, &data, &value.SnapshotAt)
	if errors.Is(err, sql.ErrNoRows) {
		return value, nil
	}
	if err != nil {
		return value, errors.New("cannot read device services")
	}
	if data != "" {
		value.Data = new(protocol.Services)
		if json.Unmarshal([]byte(data), value.Data) != nil {
			return value, errors.New("cannot decode device services")
		}
	}
	return value, nil
}
