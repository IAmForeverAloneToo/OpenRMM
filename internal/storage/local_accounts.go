package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/localaccounts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type LocalAccounts struct {
	Capability protocol.Capability     `json:"capability"`
	Status     string                  `json:"status"`
	ReportedAt int64                   `json:"reported_at"`
	SnapshotAt *int64                  `json:"snapshot_at"`
	Data       *protocol.LocalAccounts `json:"data"`
}

// RecordLocalAccounts stores the newest report after repeating device
// authorization; failed and out-of-order reports keep the last snapshot.
func (s *Store) RecordLocalAccounts(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := localaccounts.Normalize(report)
	if e != nil {
		return e
	}
	return s.recordSnapshot(ctx, "device_local_accounts", id, fingerprint, report, now)
}

func (s *Store) LocalAccounts(ctx context.Context, id string) (LocalAccounts, error) {
	v := LocalAccounts{Capability: localaccounts.Capability}
	data, e := s.readSnapshot(ctx, "device_local_accounts", id, &v.Capability, &v.Status, &v.ReportedAt, &v.SnapshotAt)
	if e != nil {
		return v, errors.New("cannot read local accounts")
	}
	if data != "" {
		v.Data = new(protocol.LocalAccounts)
		if json.Unmarshal([]byte(data), v.Data) != nil || !localaccounts.Valid(*v.Data) {
			return v, errors.New("cannot decode local accounts")
		}
	}
	return v, nil
}
