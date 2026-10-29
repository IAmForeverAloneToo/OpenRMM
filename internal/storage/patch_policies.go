package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/patching"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"sort"
	"time"
)

type PatchPolicy struct {
	ID         string              `json:"id"`
	Revision   int64               `json:"revision"`
	State      string              `json:"state"`
	Definition patching.Definition `json:"definition"`
	NextAt     int64               `json:"next_at"`
	Actor      string              `json:"actor"`
	CreatedAt  int64               `json:"created_at"`
	UpdatedAt  int64               `json:"updated_at"`
}
type PatchChange struct {
	Action, ID string
	Revision   int64
	Enabled    bool
	Definition patching.Definition
	Groups     []string
}
type PatchTarget struct{ ID, Hostname string }
type PatchReview struct {
	Change  PatchChange
	Policy  PatchPolicy
	Targets []PatchTarget
	Digest  string
}
type PatchGuard struct {
	DeviceID    string `json:"device_id"`
	Hostname    string `json:"hostname"`
	Hold        string `json:"hold"`
	OwnerRun    string `json:"owner_run"`
	RebootSince *int64 `json:"reboot_since"`
	DeferUntil  int64  `json:"defer_until"`
	Revision    int64  `json:"revision"`
}

func patchOwner(ctx context.Context, tx *sql.Tx, actor string) error {
	var owner string
	if e := tx.QueryRowContext(ctx, "SELECT username FROM administrators WHERE id=1 AND mfa_confirmed=1").Scan(&owner); e != nil {
		return e
	}
	if owner != actor {
		return patching.ErrInvalid
	}
	return nil
}

const patchPolicyColumns = "id,revision,state,definition_json,next_at,actor,created_at,updated_at"

func scanPatchPolicy(row interface{ Scan(...any) error }) (PatchPolicy, error) {
	var p PatchPolicy
	var raw string
	e := row.Scan(&p.ID, &p.Revision, &p.State, &raw, &p.NextAt, &p.Actor, &p.CreatedAt, &p.UpdatedAt)
	if e == nil && (json.Unmarshal([]byte(raw), &p.Definition) != nil || !patching.Valid(p.Definition)) {
		return p, patching.ErrInvalid
	}
	return p, e
}

// patchPoliciesTx returns the readable policies and, separately, those whose
// stored definition cannot be read: one damaged row must not stop patching.
func patchPoliciesTx(ctx context.Context, tx *sql.Tx) ([]PatchPolicy, []PatchPolicy, error) {
	rows, e := tx.QueryContext(ctx, "SELECT "+patchPolicyColumns+" FROM patch_policies ORDER BY created_at,id LIMIT 100")
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	out, damaged := []PatchPolicy{}, []PatchPolicy{}
	for rows.Next() {
		p, e := scanPatchPolicy(rows)
		if errors.Is(e, patching.ErrInvalid) && p.ID != "" {
			damaged = append(damaged, p)
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		out = append(out, p)
	}
	return out, damaged, rows.Err()
}

// pauseDamagedPatchPolicies pauses (once) active policies that cannot be read.
func pauseDamagedPatchPolicies(ctx context.Context, tx *sql.Tx, damaged []PatchPolicy, now time.Time) error {
	for _, p := range damaged {
		if p.State != "active" {
			continue
		}
		if _, e := tx.ExecContext(ctx, "UPDATE patch_policies SET state='paused',revision=revision+1,updated_at=? WHERE id=?", now.Unix(), p.ID); e != nil {
			return e
		}
		if e := auditDevice(ctx, tx, now, "server", "patch_policy_damaged", p.ID, "paused"); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) PatchPolicies(ctx context.Context) ([]PatchPolicy, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	p, _, e := patchPoliciesTx(ctx, tx)
	if e != nil {
		return nil, e
	}
	return p, tx.Commit()
}
func patchTargetsTx(ctx context.Context, tx *sql.Tx, ids, groups []string) ([]PatchTarget, error) {
	if len(ids) > 25 || len(groups) > 25 || len(ids)+len(groups) == 0 {
		return nil, patching.ErrInvalid
	}
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return nil, e
	}
	devices, gset := map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		if !protocol.ValidID(id) || devices[id] {
			return nil, patching.ErrInvalid
		}
		devices[id] = true
	}
	for _, id := range groups {
		if !ValidOrganizationID(id) || gset[id] {
			return nil, patching.ErrInvalid
		}
		found := false
		for _, g := range o.Groups {
			if g.ID == id {
				found = true
			}
		}
		if !found {
			return nil, patching.ErrInvalid
		}
		gset[id] = true
	}
	result := []PatchTarget{}
	matched := map[string]bool{}
	for _, d := range o.Devices {
		if !devices[d.ID] && !gset[d.GroupID] {
			continue
		}
		var os string
		if e = tx.QueryRowContext(ctx, "SELECT os FROM devices WHERE id=? AND revoked_at IS NULL", d.ID).Scan(&os); e != nil || os != "windows" {
			return nil, patching.ErrInvalid
		}
		result = append(result, PatchTarget{d.ID, d.Hostname})
		matched[d.ID] = true
	}
	for id := range devices {
		if !matched[id] {
			return nil, patching.ErrInvalid
		}
	}
	if len(result) == 0 || len(result) > 25 {
		return nil, patching.ErrInvalid
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
func patchConflicts(ctx context.Context, tx *sql.Tx, p PatchPolicy) error {
	if p.State != "active" {
		return nil
	}
	for _, id := range p.Definition.Devices {
		var n int
		if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM patch_policies p,json_each(CASE WHEN json_valid(p.definition_json) THEN p.definition_json ELSE '{}' END,'$.devices') d WHERE p.id<>? AND p.state='active' AND d.value=?`, p.ID, id).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return patching.ErrInvalid
		}
	}
	return nil
}
func patchDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Store) ChangePatchPolicy(ctx context.Context, c PatchChange, actor, digest string, now time.Time) (PatchReview, error) {
	r := PatchReview{Change: c}
	if !protocol.ValidID(c.ID) || c.Revision < 0 || c.Revision > 1000000 {
		return r, patching.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return r, e
	}
	defer tx.Rollback()
	if e = patchOwner(ctx, tx, actor); e != nil {
		return r, e
	}
	old, e := scanPatchPolicy(tx.QueryRowContext(ctx, "SELECT "+patchPolicyColumns+" FROM patch_policies WHERE id=?", c.ID))
	exists := e == nil
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return r, e
	}
	if exists && (old.Revision != c.Revision || old.State == "archived") || !exists && c.Revision != 0 {
		return r, patching.ErrInvalid
	}
	p := old
	switch c.Action {
	case "save":
		targets, e := patchTargetsTx(ctx, tx, c.Definition.Devices, c.Groups)
		if e != nil {
			return r, e
		}
		r.Targets = targets
		d := c.Definition
		d.Devices = nil
		for _, v := range targets {
			d.Devices = append(d.Devices, v.ID)
		}
		d = patching.Normalize(d)
		if !patching.Valid(d) {
			return r, patching.ErrInvalid
		}
		p = PatchPolicy{ID: c.ID, Revision: c.Revision + 1, State: "paused", Definition: d, NextAt: patching.Next(d, now.Add(time.Minute)).Unix(), Actor: actor, CreatedAt: old.CreatedAt, UpdatedAt: now.Unix()}
		if !exists {
			p.CreatedAt = now.Unix()
		}
		if c.Enabled {
			p.State = "active"
		}
	case "pause", "resume", "archive":
		if !exists {
			return r, patching.ErrInvalid
		}
		p.Revision++
		p.Actor = actor
		p.UpdatedAt = now.Unix()
		p.State = map[string]string{"pause": "paused", "resume": "active", "archive": "archived"}[c.Action]
		p.NextAt = patching.Next(p.Definition, now.Add(time.Minute)).Unix()
		targets, e := patchTargetsTx(ctx, tx, p.Definition.Devices, nil)
		if e != nil && c.Action == "resume" {
			return r, e
		}
		r.Targets = targets
	default:
		return r, patching.ErrInvalid
	}
	if e = patchConflicts(ctx, tx, p); e != nil {
		return r, e
	}
	if !exists {
		var n int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM patch_policies").Scan(&n); e != nil {
			return r, e
		}
		if n >= 100 {
			return r, patching.ErrInvalid
		}
	}
	r.Policy = p
	preview := p
	preview.CreatedAt = 0
	preview.UpdatedAt = 0
	r.Digest = patchDigest(struct {
		Change  PatchChange
		Policy  PatchPolicy
		Targets []PatchTarget
		Actor   string
	}{c, preview, r.Targets, actor})
	if digest == "" {
		return r, nil
	}
	if digest != r.Digest {
		return r, patching.ErrInvalid
	}
	if exists {
		if e = cancelPatchRunsTx(ctx, tx, c.ID, now, "policy_changed"); e != nil {
			return r, e
		}
	}
	raw, _ := json.Marshal(p.Definition)
	if _, e = tx.ExecContext(ctx, `INSERT INTO patch_policies(`+patchPolicyColumns+`) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,state=excluded.state,definition_json=excluded.definition_json,next_at=excluded.next_at,actor=excluded.actor,updated_at=excluded.updated_at`, p.ID, p.Revision, p.State, string(raw), p.NextAt, p.Actor, p.CreatedAt, p.UpdatedAt); e != nil {
		return r, e
	}
	if e = auditDevice(ctx, tx, now, actor, "patch_policy_"+c.Action, c.ID, p.State); e != nil {
		return r, e
	}
	return r, tx.Commit()
}
func patchGuardTx(ctx context.Context, tx *sql.Tx, id string) (PatchGuard, error) {
	g := PatchGuard{DeviceID: id}
	if _, e := tx.ExecContext(ctx, "INSERT INTO patch_device_guards(device_id)VALUES(?) ON CONFLICT DO NOTHING", id); e != nil {
		return g, e
	}
	e := tx.QueryRowContext(ctx, `SELECT g.hold,g.owner_run,g.reboot_since,g.defer_until,g.revision,d.hostname FROM patch_device_guards g JOIN devices d ON d.id=g.device_id WHERE g.device_id=?`, id).Scan(&g.Hold, &g.OwnerRun, &g.RebootSince, &g.DeferUntil, &g.Revision, &g.Hostname)
	return g, e
}
func (s *Store) PatchGuards(ctx context.Context) ([]PatchGuard, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT g.device_id,d.hostname,g.hold,g.owner_run,g.reboot_since,g.defer_until,g.revision FROM patch_device_guards g JOIN devices d ON d.id=g.device_id ORDER BY d.hostname,g.device_id LIMIT 1000`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []PatchGuard{}
	for rows.Next() {
		var g PatchGuard
		if e = rows.Scan(&g.DeviceID, &g.Hostname, &g.Hold, &g.OwnerRun, &g.RebootSince, &g.DeferUntil, &g.Revision); e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) ChangePatchGuard(ctx context.Context, id, action string, revision, until int64, actor, digest string, now time.Time) (PatchGuard, string, error) {
	var g PatchGuard
	if !protocol.ValidID(id) || action != "acknowledge" && action != "defer" {
		return g, "", patching.ErrInvalid
	}
	if action == "defer" && (until <= now.Unix() || until > now.Add(168*time.Hour).Unix()) || action == "acknowledge" && until != 0 {
		return g, "", patching.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return g, "", e
	}
	defer tx.Rollback()
	if e = patchOwner(ctx, tx, actor); e != nil {
		return g, "", e
	}
	g, e = patchGuardTx(ctx, tx, id)
	if e != nil {
		return g, "", e
	}
	if g.Revision != revision || action == "defer" && g.Hold == "restart_requested" {
		return g, "", patching.ErrInvalid
	}
	var pending int
	if e = tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM update_jobs WHERE device_id=? AND status IN('queued','dispatched'))+(SELECT COUNT(*) FROM patch_runs WHERE device_id=? AND finished_at IS NULL)", id, id).Scan(&pending); e != nil {
		return g, "", e
	}
	if pending != 0 {
		return g, "", patching.ErrInvalid
	}
	expected := patchDigest(struct {
		Guard         PatchGuard
		Action, Actor string
		Until         int64
	}{g, action, actor, until})
	if digest == "" {
		return g, expected, nil
	}
	if expected != digest {
		return g, "", patching.ErrInvalid
	}
	if action == "acknowledge" {
		g.Hold = ""
		g.OwnerRun = ""
	} else {
		g.DeferUntil = until
	}
	if _, e = tx.ExecContext(ctx, "UPDATE patch_device_guards SET hold=?,owner_run=?,defer_until=?,revision=revision+1 WHERE device_id=?", g.Hold, g.OwnerRun, g.DeferUntil, id); e != nil {
		return g, "", e
	}
	if e = auditDevice(ctx, tx, now, actor, "patch_guard_"+action, id, "reviewed"); e != nil {
		return g, "", e
	}
	g.Revision++
	return g, expected, tx.Commit()
}
