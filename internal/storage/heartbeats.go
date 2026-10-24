package storage

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// RecordHeartbeat repeats authorization inside the write so a concurrent revoke
// or superseding renewal cannot turn an earlier successful check into a write.
// Only server receipt time is stored; a clock correction cannot move it back.
func (s *Store) RecordHeartbeat(ctx context.Context, id, fingerprint string, input protocol.Heartbeat, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	locks := input.Locked
	if locks == nil {
		locks = []string{}
	}
	rawLocks, _ := json.Marshal(locks)
	abilities := input.Abilities
	if abilities == nil {
		abilities = []string{}
	}
	rawAbilities, _ := json.Marshal(abilities)
	result, err := tx.ExecContext(ctx, `UPDATE devices SET hostname=?,os=?,architecture=?,agent_version=?,feature_locks_json=?,abilities_json=?,
        last_contact_at=MAX(COALESCE(last_contact_at,0),?)
        WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, input.Hostname, input.OS, input.Architecture, input.AgentVersion, string(rawLocks), string(rawAbilities), now.Unix(), id, fingerprint, fingerprint, now.Unix())
	if err != nil {
		return errors.New("cannot record device heartbeat")
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrAuthentication
	}
	if err = captureAlert(ctx, tx, id, "offline", "ok", nil, now); err != nil {
		return err
	}
	if input.Isolation != nil {
		if err = recordIsolation(ctx, tx, id, *input.Isolation, now); err != nil {
			return errors.New("cannot record device isolation")
		}
	}
	return tx.Commit()
}

// FeatureLocks are the features the device's agent last reported as locked
// off by its local administrator, sorted.
func (s *Store) FeatureLocks(ctx context.Context, id string) ([]string, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, "SELECT feature_locks_json FROM devices WHERE id=?", id).Scan(&raw); err != nil {
		return nil, err
	}
	locks := []string{}
	if json.Unmarshal([]byte(raw), &locks) != nil || !protocol.ValidFeatureList(locks) {
		return []string{}, nil
	}
	return locks, nil
}

// DisabledFeatures is what the device's effective monitoring policy turns off
// (device policy, else its group's policy, else nothing), sorted.
func (s *Store) DisabledFeatures(ctx context.Context, id string) ([]string, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT CASE WHEN o.policy_id IS NOT NULL THEN dp.features_json WHEN g.policy_id IS NOT NULL THEN gp.features_json ELSE '{}' END
        FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id LEFT JOIN monitoring_policies dp ON dp.id=o.policy_id
        LEFT JOIN device_groups g ON g.id=o.group_id LEFT JOIN monitoring_policies gp ON gp.id=g.policy_id WHERE d.id=?`, id).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var f map[string]bool
	if json.Unmarshal([]byte(raw), &f) != nil {
		return nil, ErrOrganization
	}
	f, ok := normalizeFeatures(f)
	if !ok {
		return nil, ErrOrganization
	}
	return disabledList(f), nil
}

// HasAbility reports whether the device's agent last reported an ability
// (protocol.Heartbeat.Abilities).
func (s *Store) HasAbility(ctx context.Context, id, ability string) bool {
	var raw string
	if s.db.QueryRowContext(ctx, "SELECT abilities_json FROM devices WHERE id=? AND revoked_at IS NULL", id).Scan(&raw) != nil {
		return false
	}
	abilities := []string{}
	return json.Unmarshal([]byte(raw), &abilities) == nil && protocol.ValidAbilities(abilities) && slices.Contains(abilities, ability)
}
