package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// snapshotTables hold only the newest report per device. The
// table name is a fixed identifier from this list, never input.
var snapshotTables = map[string]bool{"device_local_accounts": true, "device_system_info": true, "device_security": true}

// recordSnapshot stores an already normalized report for an authorized
// device; failed and out-of-order reports keep the last good snapshot.
func (s *Store) recordSnapshot(ctx context.Context, table, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	if !snapshotTables[table] {
		return errors.New("unknown snapshot table")
	}
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	result, e := s.db.ExecContext(ctx, `INSERT INTO `+table+`(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at)
 SELECT id,?,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))
 ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,
 snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE `+table+`.snapshot_json END,
 snapshot_at=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_at ELSE `+table+`.snapshot_at END
 WHERE excluded.reported_at>=`+table+`.reported_at`, report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, id, fingerprint, fingerprint, now.Unix())
	if e != nil {
		return errors.New("cannot persist device report")
	}
	if n, e := result.RowsAffected(); e != nil {
		return errors.New("cannot persist device report")
	} else if n == 0 {
		// Either the device is not authorized or the report is out of order.
		var allowed int
		if s.db.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&allowed) != nil {
			return ErrAuthentication
		}
	}
	return nil
}

// readSnapshot returns status "not_reported" when the device never reported.
func (s *Store) readSnapshot(ctx context.Context, table, id string, capability *protocol.Capability, status *string, reportedAt *int64, snapshotAt **int64) (string, error) {
	if !snapshotTables[table] {
		return "", errors.New("unknown snapshot table")
	}
	*status = "not_reported"
	var data string
	e := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at FROM `+table+` WHERE device_id=?`, id).Scan(&capability.Version, status, reportedAt, &data, snapshotAt)
	if errors.Is(e, sql.ErrNoRows) {
		*status = "not_reported"
		return "", nil
	}
	if e != nil {
		return "", errors.New("cannot read device report")
	}
	return data, nil
}
