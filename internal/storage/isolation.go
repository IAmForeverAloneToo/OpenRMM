package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/isolation"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Network isolation. Isolate and release are mutating response
// actions bound to a case or, without one, recorded in the audit log
// (LiveCase). They are handed out before other work and are not held back
// by the per-device collection limits. Each isolation gets a one-time
// release code for the local break-glass command; the agent receives only
// its hash. The device's state comes from its heartbeats.

var (
	ErrIsolation = errors.New("isolation unavailable; check the device, its agent and incident response")
	// ErrIsolationBusy: the device is isolated or an isolation is under way.
	ErrIsolationBusy = errors.New("the device is already isolated or being isolated")
	// ErrNotIsolated: there is no isolation to release.
	ErrNotIsolated = errors.New("the device is not isolated")
)

// Isolation is a device's newest isolation with its state.
type Isolation struct {
	ID                 string   `json:"id"`
	DeviceID           string   `json:"device_id"`
	CaseID             string   `json:"case_id"`
	Actor              string   `json:"actor"`
	Code               string   `json:"code,omitempty"`
	Allow              []string `json:"allow"`
	ReleaseAfter       int64    `json:"release_after"`
	IsolateJob         string   `json:"isolate_job"`
	ReleaseJob         string   `json:"release_job,omitempty"`
	RequestedAt        int64    `json:"requested_at"`
	IsolatedAt         *int64   `json:"isolated_at"`
	ReleaseRequestedAt *int64   `json:"release_requested_at"`
	ReleaseActor       string   `json:"release_actor,omitempty"`
	ReleasedAt         *int64   `json:"released_at"`
	ReleaseReason      string   `json:"release_reason,omitempty"`
	// Phase is isolating, isolated, releasing or released.
	Phase string `json:"phase"`
}

// ReleaseCode is a one-time code of 12 characters from an alphabet without
// look-alikes, grouped in fours.
func ReleaseCode() (string, error) {
	const alphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
	b := make([]byte, 12)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	out := make([]byte, 0, 14)
	for i, v := range b {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, alphabet[int(v)%len(alphabet)])
	}
	return string(out), nil
}

// IsolationAllow is the effective policy's isolation allow list.
func (s *Store) IsolationAllow(ctx context.Context, id string) ([]string, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT CASE WHEN o.policy_id IS NOT NULL THEN dp.isolation_allow_json WHEN g.policy_id IS NOT NULL THEN gp.isolation_allow_json ELSE '[]' END
        FROM devices d LEFT JOIN device_organization o ON o.device_id=d.id LEFT JOIN monitoring_policies dp ON dp.id=o.policy_id
        LEFT JOIN device_groups g ON g.id=o.group_id LEFT JOIN monitoring_policies gp ON gp.id=g.policy_id WHERE d.id=?`, id).Scan(&raw)
	if err != nil {
		return nil, err
	}
	list := []string{}
	if json.Unmarshal([]byte(raw), &list) != nil || !protocol.ValidAllowList(list) {
		return nil, ErrOrganization
	}
	return list, nil
}

// isolationGrace is how long after its isolate action finished a device has
// to report the isolation before the isolation counts as failed (several
// heartbeats, with retries). A later report still reopens it.
const isolationGrace = 15 * time.Minute

// closeFailedIsolations closes isolations whose isolate action ended (failed,
// expired, cancelled, or ran without isolating: for example the server's
// address was unknown) while the device never reported being isolated; ""
// closes them on every device.
func closeFailedIsolations(ctx context.Context, tx *sql.Tx, device string, now time.Time) error {
	_, e := tx.ExecContext(ctx, `UPDATE device_isolations SET released_at=?,release_reason='failed' WHERE (?='' OR device_id=?) AND released_at IS NULL AND isolated_at IS NULL
 AND (SELECT isolated FROM devices WHERE id=device_isolations.device_id)=0
 AND EXISTS (SELECT 1 FROM evidence_jobs j WHERE j.id=device_isolations.isolate_job AND j.status IN ('succeeded','failed','expired','cancelled') AND COALESCE(j.finished_at,0)<=?)`, now.Unix(), device, device, now.Add(-isolationGrace).Unix())
	return e
}

// queueIsolationJob inserts an isolate or release job for the device.
func queueIsolationJob(ctx context.Context, tx *sql.Tx, caseID, device, actor string, a protocol.ResponseAction, now time.Time) (string, error) {
	job, e := evidenceID()
	if e != nil {
		return "", e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO evidence_jobs(id,case_id,device_id,actor,path,status,chunk_size,created_at,expires_at,source,action) VALUES(?,?,?,?,?,'queued',?,?,?,'file',?)`, job, caseID, device, actor, a.Label(), EvidenceChunk, now.Unix(), now.Add(evidenceQueueLife).Unix(), a.Text()); e != nil {
		return "", ErrIsolation
	}
	// The release code is never put in the custody log or audit details.
	if _, e = AppendCustody(ctx, tx, caseID, actor, device, "action_requested", map[string]string{"job": job, "action": a.Label()}, nil, "success", now); e != nil {
		return "", e
	}
	return job, nil
}

// isolationReady checks the device, its agent and incident response, read
// before the write transaction (the store has a single connection).
func (s *Store) isolationReady(ctx context.Context, device string) error {
	if s.evidence == "" || !protocol.ValidID(device) {
		return ErrIsolation
	}
	disabled, e1 := s.DisabledFeatures(ctx, device)
	locks, e2 := s.FeatureLocks(ctx, device)
	if e1 != nil || e2 != nil || slices.Contains(disabled, "response") || slices.Contains(locks, "response") {
		return ErrIsolation
	}
	if !s.HasAbility(ctx, device, protocol.AbilityIsolation) {
		return ErrActionUnsupported
	}
	return nil
}

// IsolateDevice asks the device to isolate itself, into caseID or LiveCase.
// releaseAfter (seconds, 0 for none) releases it automatically.
func (s *Store) IsolateDevice(ctx context.Context, caseID, device, actor string, releaseAfter int64, now time.Time) (Isolation, error) {
	if caseID != LiveCase && !protocol.ValidID(caseID) || releaseAfter < 0 || releaseAfter > protocol.MaxReleaseAfter {
		return Isolation{}, ErrIsolation
	}
	if e := s.isolationReady(ctx, device); e != nil {
		return Isolation{}, e
	}
	allow, e := s.IsolationAllow(ctx, device)
	if e != nil {
		return Isolation{}, e
	}
	code, e := ReleaseCode()
	if e != nil {
		return Isolation{}, e
	}
	spec := protocol.IsolationSpec{Allow: allow, CodeHash: isolation.HashCode(code), ReleaseAfter: releaseAfter}
	a := protocol.ResponseAction{Kind: "isolate", Isolate: &spec}
	if !a.Valid() {
		return Isolation{}, ErrIsolation
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Isolation{}, e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, actor, device, "response"); e != nil {
		return Isolation{}, e
	}
	if e = closeFailedIsolations(ctx, tx, device, now); e != nil {
		return Isolation{}, e
	}
	var open, isolated int
	if e = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM device_isolations WHERE device_id=? AND released_at IS NULL),COALESCE((SELECT isolated FROM devices WHERE id=? AND revoked_at IS NULL),-1)`, device, device).Scan(&open, &isolated); e != nil || isolated < 0 {
		return Isolation{}, ErrIsolation
	}
	if open > 0 || isolated == 1 {
		return Isolation{}, ErrIsolationBusy
	}
	if caseID != LiveCase {
		var status string
		if e = tx.QueryRowContext(ctx, `SELECT status FROM cases WHERE id=?`, caseID).Scan(&status); e != nil || status != "open" {
			return Isolation{}, ErrCase
		}
	}
	job, e := queueIsolationJob(ctx, tx, caseID, device, actor, a, now)
	if e != nil {
		return Isolation{}, e
	}
	id, e := evidenceID()
	if e != nil {
		return Isolation{}, e
	}
	rawAllow, _ := json.Marshal(allow)
	if _, e = tx.ExecContext(ctx, `INSERT INTO device_isolations(id,device_id,case_id,actor,code,allow_json,release_after,isolate_job,requested_at) VALUES(?,?,?,?,?,?,?,?,?)`, id, device, caseID, actor, code, string(rawAllow), releaseAfter, job, now.Unix()); e != nil {
		return Isolation{}, ErrIsolation
	}
	if e = tx.Commit(); e != nil {
		return Isolation{}, e
	}
	return s.DeviceIsolation(ctx, device)
}

// ReleaseDevice asks an isolated (or isolating) device to lift isolation.
func (s *Store) ReleaseDevice(ctx context.Context, device, actor string, now time.Time) (Isolation, error) {
	if !protocol.ValidID(device) || s.evidence == "" {
		return Isolation{}, ErrIsolation
	}
	cur, e := s.DeviceIsolation(ctx, device)
	if e != nil {
		return Isolation{}, e
	}
	var isolated int
	_ = s.db.QueryRowContext(ctx, `SELECT isolated FROM devices WHERE id=?`, device).Scan(&isolated)
	if cur.ID == "" || cur.ReleasedAt != nil && isolated == 0 {
		return Isolation{}, ErrNotIsolated
	}
	if cur.ReleaseJob != "" {
		// A release under way is not repeated; one that did not get through
		// (expired while the device was offline, refused, unknown) is.
		var status string
		_ = s.db.QueryRowContext(ctx, `SELECT status FROM evidence_jobs WHERE id=?`, cur.ReleaseJob).Scan(&status)
		if status == "queued" || status == "dispatched" || status == "uploading" || status == "verifying" || status == "succeeded" && isolated == 0 {
			return cur, nil
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Isolation{}, e
	}
	defer tx.Rollback()
	if e = authorizeActor(ctx, tx, actor, device, "response"); e != nil {
		return Isolation{}, e
	}
	// An isolation reopened by a late report is open again for release.
	if _, e = tx.ExecContext(ctx, `UPDATE device_isolations SET released_at=NULL,release_reason='' WHERE id=? AND release_reason='failed'`, cur.ID); e != nil {
		return Isolation{}, e
	}
	// An isolate action the device has not taken yet is simply cancelled.
	r, e := tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='cancelled',outcome='cancelled',finished_at=? WHERE id=? AND status='queued'`, now.Unix(), cur.IsolateJob)
	if e != nil {
		return Isolation{}, e
	}
	if n, _ := r.RowsAffected(); n == 1 {
		if _, e = AppendCustody(ctx, tx, cur.CaseID, actor, device, "action_cancelled", map[string]string{"job": cur.IsolateJob, "reason": "released before the device took it"}, nil, "cancelled", now); e != nil {
			return Isolation{}, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE device_isolations SET release_requested_at=?,release_actor=?,released_at=?,release_reason='server',code='' WHERE id=? AND released_at IS NULL`, now.Unix(), actor, now.Unix(), cur.ID); e != nil {
			return Isolation{}, e
		}
	} else {
		job, e := queueIsolationJob(ctx, tx, cur.CaseID, device, actor, protocol.ResponseAction{Kind: "release"}, now)
		if e != nil {
			return Isolation{}, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE device_isolations SET release_job=?,release_requested_at=?,release_actor=? WHERE id=? AND released_at IS NULL`, job, now.Unix(), actor, cur.ID); e != nil {
			return Isolation{}, e
		}
	}
	if e = tx.Commit(); e != nil {
		return Isolation{}, e
	}
	return s.DeviceIsolation(ctx, device)
}

// DeviceIsolation is the device's newest isolation (ID "" when it was never
// isolated); an isolation that failed is closed first.
func (s *Store) DeviceIsolation(ctx context.Context, device string) (Isolation, error) {
	v := Isolation{Allow: []string{}}
	if tx, e := s.db.BeginTx(ctx, nil); e == nil {
		if closeFailedIsolations(ctx, tx, device, time.Now()) == nil {
			_ = tx.Commit()
		}
		_ = tx.Rollback()
	}
	var allow string
	var isolated int
	e := s.db.QueryRowContext(ctx, `SELECT i.id,i.device_id,i.case_id,i.actor,i.code,i.allow_json,i.release_after,i.isolate_job,i.release_job,i.requested_at,i.isolated_at,i.release_requested_at,i.release_actor,i.released_at,i.release_reason,d.isolated
 FROM device_isolations i JOIN devices d ON d.id=i.device_id WHERE i.device_id=? ORDER BY i.released_at IS NULL DESC,i.requested_at DESC,i.rowid DESC LIMIT 1`, device).Scan(&v.ID, &v.DeviceID, &v.CaseID, &v.Actor, &v.Code, &allow, &v.ReleaseAfter, &v.IsolateJob, &v.ReleaseJob, &v.RequestedAt, &v.IsolatedAt, &v.ReleaseRequestedAt, &v.ReleaseActor, &v.ReleasedAt, &v.ReleaseReason, &isolated)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	_ = json.Unmarshal([]byte(allow), &v.Allow)
	v.Phase = isolationPhase(v.ReleasedAt != nil, v.ReleaseRequestedAt != nil, isolated == 1)
	if v.ReleaseReason == "failed" {
		v.Phase = "failed"
	}
	if v.ReleasedAt != nil && v.ReleaseReason != "failed" {
		v.Code = "" // a used or retired code is never shown again
	}
	return v, nil
}

func isolationPhase(released, releasing, isolated bool) string {
	switch {
	case released:
		return "released"
	case releasing:
		return "releasing"
	case isolated:
		return "isolated"
	}
	return "isolating"
}

// IsolationPhases maps devices with an isolation under way or in force to
// its phase, for the device list (one query).
func (s *Store) IsolationPhases(ctx context.Context) (map[string]string, error) {
	if tx, e := s.db.BeginTx(ctx, nil); e == nil {
		if closeFailedIsolations(ctx, tx, "", time.Now()) == nil {
			_ = tx.Commit()
		}
		_ = tx.Rollback()
	}
	rows, e := s.db.QueryContext(ctx, `SELECT d.id,d.isolated,(SELECT COUNT(*) FROM device_isolations i WHERE i.device_id=d.id AND i.released_at IS NULL),
 (SELECT COUNT(*) FROM device_isolations i WHERE i.device_id=d.id AND i.released_at IS NULL AND i.release_requested_at IS NOT NULL)
 FROM devices d WHERE d.isolated=1 OR EXISTS (SELECT 1 FROM device_isolations i WHERE i.device_id=d.id AND i.released_at IS NULL)`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id string
		var isolated, open, releasing int
		if e = rows.Scan(&id, &isolated, &open, &releasing); e != nil {
			return nil, e
		}
		out[id] = isolationPhase(open == 0 && isolated == 0, releasing > 0, isolated == 1)
		if open == 0 && isolated == 1 {
			out[id] = "isolated" // isolated without a record (for example restored from a backup)
		}
	}
	return out, rows.Err()
}

// recordIsolation stores the isolation state a heartbeat reports and closes
// the isolation record when the agent reports a release (by the server, the
// timed release or the local break-glass command).
func recordIsolation(ctx context.Context, tx *sql.Tx, device string, st protocol.IsolationState, now time.Time) error {
	raw, _ := json.Marshal(st)
	if _, e := tx.ExecContext(ctx, `UPDATE devices SET isolation_json=?,isolated=? WHERE id=?`, string(raw), st.Isolated, device); e != nil {
		return e
	}
	if st.Isolated {
		_, e := tx.ExecContext(ctx, `UPDATE device_isolations SET isolated_at=COALESCE(isolated_at,?),released_at=CASE WHEN release_reason='failed' THEN NULL ELSE released_at END,release_reason=CASE WHEN release_reason='failed' THEN '' ELSE release_reason END
 WHERE device_id=? AND isolate_job=? AND (released_at IS NULL OR release_reason='failed')`, now.Unix(), device, st.Job)
		return e
	}
	if st.Released == "" || st.Job == "" {
		return nil
	}
	var id, caseID string
	e := tx.QueryRowContext(ctx, `SELECT id,case_id FROM device_isolations WHERE device_id=? AND isolate_job=? AND (released_at IS NULL OR release_reason='failed')`, device, st.Job).Scan(&id, &caseID)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE device_isolations SET released_at=?,release_reason=?,code='' WHERE id=?`, now.Unix(), st.Released, id); e != nil {
		return e
	}
	if st.Released != "server" {
		label := map[string]string{"break_glass": "released locally with the release code", "timed": "released automatically (timed release)"}[st.Released]
		if _, e = AppendCustody(ctx, tx, caseID, "device", device, "isolation_released", map[string]string{"how": label, "at": st.ReleasedAt}, nil, "success", now); e != nil {
			return e
		}
	}
	return nil
}

// ReportedIsolation is the isolation state the device's agent last reported
// (empty when it never reported one).
func (s *Store) ReportedIsolation(ctx context.Context, device string) (protocol.IsolationState, error) {
	var raw string
	var v protocol.IsolationState
	if e := s.db.QueryRowContext(ctx, `SELECT isolation_json FROM devices WHERE id=?`, device).Scan(&raw); e != nil {
		return v, e
	}
	if raw != "" && (json.Unmarshal([]byte(raw), &v) != nil || !v.Valid()) {
		return protocol.IsolationState{}, nil
	}
	return v, nil
}
