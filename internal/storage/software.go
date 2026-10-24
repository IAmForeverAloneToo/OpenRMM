package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
)

const SoftwareHistoryLimit = 200
const softwareGlobalHistoryLimit = 5000
const SoftwareHistoryDays = 30

type Software struct {
	Capability    protocol.Capability `json:"capability"`
	Status        string              `json:"status"`
	ReportedAt    int64               `json:"reported_at"`
	SnapshotAt    *int64              `json:"snapshot_at"`
	Data          *protocol.Software  `json:"data"`
	BaselineReady bool                `json:"baseline_ready"`
}
type SoftwareChange struct {
	ID         int64                   `json:"id"`
	FromAt     int64                   `json:"from_at"`
	ObservedAt int64                   `json:"observed_at"`
	Kind       string                  `json:"kind"`
	Before     *protocol.SoftwareEntry `json:"before"`
	After      *protocol.SoftwareEntry `json:"after"`
}

func softwareDifferences(old, next protocol.Software, from, to int64) []SoftwareChange {
	// Per-user registrations are compared only for users whose
	// hive was read in both reports: a user signing out or in is no change.
	both := map[string]bool{}
	for _, u := range old.Users {
		both[u.SID] = false
	}
	for _, u := range next.Users {
		if _, ok := both[u.SID]; ok {
			both[u.SID] = true
		}
	}
	a, b := map[string]protocol.SoftwareEntry{}, map[string]protocol.SoftwareEntry{}
	for _, x := range old.Entries {
		if x.View != "user" || both[x.UserSID] {
			a[x.ID] = x
		}
	}
	for _, x := range next.Entries {
		if x.View != "user" || both[x.UserSID] {
			b[x.ID] = x
		}
	}
	ids := make([]string, 0, len(a)+len(b))
	for id := range a {
		ids = append(ids, id)
	}
	for id := range b {
		if _, ok := a[id]; !ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := []SoftwareChange{}
	for _, id := range ids {
		before, was := a[id]
		after, is := b[id]
		c := SoftwareChange{FromAt: from, ObservedAt: to}
		if was {
			c.Before = &before
		}
		if is {
			c.After = &after
		}
		// Skipped registrations are unidentified. When more were skipped than
		// before, a vanished entry may only have become unreadable (or been
		// pushed over the cap); when fewer, a new entry may only have become
		// readable again. Those ambiguous additions/removals are not recorded.
		// An unchanged count (for example one persistently broken registration)
		// keeps ordinary history. Changes to retained entries are exact.
		oldSkipped, nextSkipped := old.Skipped, next.Skipped
		if (was && before.View == "user") || (is && after.View == "user") {
			oldSkipped, nextSkipped = old.UserSkipped, next.UserSkipped
		}
		// The resolved account name is not part of the registration.
		same := before
		if was && is {
			same.User = after.User
		}
		switch {
		case !was && oldSkipped > nextSkipped, !is && nextSkipped > oldSkipped:
			continue
		case !was:
			c.Kind = "added"
		case !is:
			c.Kind = "removed"
		case before.Version != after.Version:
			c.Kind = "version_changed"
		case same != after:
			c.Kind = "metadata_changed"
		default:
			continue
		}
		out = append(out, c)
	}
	return out
}

// Snapshot and differences commit together, after repeating certificate/device
// authorization under the same immediate transaction. Retries create no events.
func (s *Store) RecordSoftware(ctx context.Context, id, fingerprint string, report protocol.FeatureReport, now time.Time) error {
	report, e := software.Normalize(report)
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin software report")
	}
	defer tx.Rollback()
	var allowed int
	if e = tx.QueryRowContext(ctx, `SELECT 1 FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR (previous_fingerprint=? AND previous_until>?))`, id, fingerprint, fingerprint, now.Unix()).Scan(&allowed); errors.Is(e, sql.ErrNoRows) {
		return ErrAuthentication
	} else if e != nil {
		return errors.New("cannot authenticate software report")
	}
	var previous string
	var stamp sql.NullInt64
	var ready bool
	var last int64
	e = tx.QueryRowContext(ctx, `SELECT snapshot_json,snapshot_at,baseline_ready,reported_at FROM device_software WHERE device_id=?`, id).Scan(&previous, &stamp, &ready, &last)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return errors.New("cannot read software baseline")
	}
	if now.Unix() < last {
		return nil
	}
	var next protocol.Software
	if report.Status == "ok" {
		if json.Unmarshal(report.Data, &next) != nil {
			return softwareError()
		}
		if ready && stamp.Valid {
			var old protocol.Software
			if json.Unmarshal([]byte(previous), &old) != nil || !software.Valid(old) {
				return softwareError()
			}
			changes := softwareDifferences(old, next, stamp.Int64, now.Unix())
			// A large replacement is bounded too; retain only the deterministic newest
			// tail, with the same advertised rolling-history limit as ordinary reports.
			if len(changes) > SoftwareHistoryLimit {
				changes = changes[len(changes)-SoftwareHistoryLimit:]
			}
			for _, c := range changes {
				before, _ := json.Marshal(c.Before)
				after, _ := json.Marshal(c.After)
				if _, e = tx.ExecContext(ctx, `INSERT INTO software_changes(device_id,from_at,observed_at,kind,before_json,after_json) VALUES(?,?,?,?,?,?)`, id, c.FromAt, c.ObservedAt, c.Kind, string(before), string(after)); e != nil {
					return softwareError()
				}
			}
		}
	}
	var snapshotAt any
	if report.Status == "ok" {
		snapshotAt = now.Unix()
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO device_software(device_id,capability_version,last_status,reported_at,snapshot_json,snapshot_at,baseline_ready) VALUES(?,?,?,?,?,?,?)
 ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,
 snapshot_json=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_json ELSE device_software.snapshot_json END,
 snapshot_at=CASE WHEN excluded.last_status='ok' THEN excluded.snapshot_at ELSE device_software.snapshot_at END,
 baseline_ready=CASE WHEN excluded.last_status='ok' THEN 1 ELSE device_software.baseline_ready END`, id, report.Capability.Version, report.Status, now.Unix(), string(report.Data), snapshotAt, report.Status == "ok")
	if e != nil {
		return softwareError()
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM software_changes WHERE device_id=? AND id NOT IN (SELECT id FROM software_changes WHERE device_id=? ORDER BY id DESC LIMIT ?)`, id, id, SoftwareHistoryLimit); e != nil {
		return softwareError()
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM software_changes WHERE observed_at<=? OR id NOT IN (SELECT id FROM software_changes ORDER BY id DESC LIMIT ?)`, now.Add(-SoftwareHistoryDays*24*time.Hour).Unix(), softwareGlobalHistoryLimit); e != nil {
		return softwareError()
	}
	if tx.Commit() != nil {
		return softwareError()
	}
	return nil
}
func softwareError() error { return errors.New("cannot persist software inventory") }
func (s *Store) Software(ctx context.Context, id string) (Software, error) {
	v := Software{Capability: software.Capability, Status: "not_reported"}
	var data string
	e := s.db.QueryRowContext(ctx, `SELECT capability_version,last_status,reported_at,snapshot_json,snapshot_at,baseline_ready FROM device_software WHERE device_id=?`, id).Scan(&v.Capability.Version, &v.Status, &v.ReportedAt, &data, &v.SnapshotAt, &v.BaselineReady)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, errors.New("cannot read software inventory")
	}
	if data != "" {
		v.Data = new(protocol.Software)
		if json.Unmarshal([]byte(data), v.Data) != nil || !software.Valid(*v.Data) {
			return v, errors.New("cannot decode software inventory")
		}
	}
	return v, nil
}
func (s *Store) SoftwareHistory(ctx context.Context, id string, now time.Time) ([]SoftwareChange, error) {
	out := []SoftwareChange{}
	rows, e := s.db.QueryContext(ctx, `SELECT id,from_at,observed_at,kind,before_json,after_json FROM software_changes WHERE device_id=? AND observed_at>? ORDER BY id DESC LIMIT ?`, id, now.Add(-SoftwareHistoryDays*24*time.Hour).Unix(), SoftwareHistoryLimit)
	if e != nil {
		return nil, errors.New("cannot read software history")
	}
	defer rows.Close()
	for rows.Next() {
		var c SoftwareChange
		var a, b string
		if rows.Scan(&c.ID, &c.FromAt, &c.ObservedAt, &c.Kind, &a, &b) != nil || json.Unmarshal([]byte(a), &c.Before) != nil || json.Unmarshal([]byte(b), &c.After) != nil || c.Before == nil && c.After == nil || c.Before != nil && !software.EntryValid(*c.Before) || c.After != nil && !software.EntryValid(*c.After) {
			return nil, errors.New("cannot decode software history")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) PruneSoftwareHistory(ctx context.Context, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `DELETE FROM software_changes WHERE observed_at<=?`, now.Add(-SoftwareHistoryDays*24*time.Hour).Unix())
	if e != nil {
		return errors.New("cannot prune software history")
	}
	return nil
}
