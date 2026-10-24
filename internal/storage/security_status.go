package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/securitystatus"
)

type SecurityStatus struct {
	Capability protocol.Capability      `json:"capability"`
	Status     string                   `json:"status"`
	ReportedAt int64                    `json:"reported_at"`
	SnapshotAt *int64                   `json:"snapshot_at"`
	Data       *protocol.SecurityStatus `json:"data"`
}

// RecordSecurityStatus stores the newest report after repeating device
// authorization; failed and out-of-order reports keep the last snapshot.
func (s *Store) RecordSecurityStatus(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := securitystatus.Normalize(report)
	if e != nil {
		return e
	}
	if e = s.recordSnapshot(ctx, "device_security", id, fingerprint, report, now); e != nil || report.Status != "ok" {
		return e
	}
	var v protocol.SecurityStatus
	if json.Unmarshal(report.Data, &v) != nil {
		return errors.New("cannot persist security status")
	}
	bitlocker, defender := securitystatus.Summary(v)
	// Only when this report is the stored one (not out of order).
	if _, e = s.db.ExecContext(ctx, `UPDATE device_security SET bitlocker=?,defender=? WHERE device_id=? AND reported_at=? AND last_status='ok'`, bitlocker, defender, id, now.Unix()); e != nil {
		return errors.New("cannot persist security status")
	}
	return nil
}

func (s *Store) SecurityStatus(ctx context.Context, id string) (SecurityStatus, error) {
	v := SecurityStatus{Capability: securitystatus.Capability}
	data, e := s.readSnapshot(ctx, "device_security", id, &v.Capability, &v.Status, &v.ReportedAt, &v.SnapshotAt)
	if e != nil {
		return v, errors.New("cannot read security status")
	}
	if data != "" {
		v.Data = new(protocol.SecurityStatus)
		if json.Unmarshal([]byte(data), v.Data) != nil || !securitystatus.Valid(*v.Data) {
			return v, errors.New("cannot decode security status")
		}
	}
	return v, nil
}

// SecuritySummary is the fleet list's BitLocker and Defender columns from the
// last good report.
type SecuritySummary struct {
	BitLocker  string
	Defender   string
	SnapshotAt int64
}

// SecuritySummaries reads the stored summary columns; it never decodes the
// reports themselves.
func (s *Store) SecuritySummaries(ctx context.Context) (map[string]SecuritySummary, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT device_id,bitlocker,defender,snapshot_at FROM device_security WHERE snapshot_json<>'' AND snapshot_at IS NOT NULL`)
	if e != nil {
		return nil, errors.New("cannot read security status")
	}
	defer rows.Close()
	out := map[string]SecuritySummary{}
	for rows.Next() {
		var id string
		var v SecuritySummary
		if rows.Scan(&id, &v.BitLocker, &v.Defender, &v.SnapshotAt) != nil {
			return nil, errors.New("cannot read security status")
		}
		out[id] = v
	}
	return out, rows.Err()
}
