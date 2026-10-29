package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"sort"
	"time"
)

const ScriptBatchTargets = 25

var ErrScriptBatch = errors.New("batch changed or unavailable; review targets, local permissions and pending work again")

type ScriptBatchChange struct {
	ID        string            `json:"id"`
	VersionID string            `json:"version_id"`
	Name      string            `json:"name"`
	Devices   []string          `json:"devices"`
	Groups    []string          `json:"groups"`
	Arguments map[string]string `json:"arguments"`
}
type ScriptBatchTarget struct {
	ID              string `json:"device_id"`
	Hostname        string `json:"hostname"`
	RunID           string `json:"run_id"`
	Status          string `json:"status,omitempty"`
	CancelRequested bool   `json:"cancel_requested,omitempty"`
}
type ScriptBatch struct {
	Change    ScriptBatchChange   `json:"change"`
	Actor     string              `json:"actor"`
	Digest    string              `json:"digest"`
	Targets   []ScriptBatchTarget `json:"targets"`
	Version   ScriptVersion       `json:"version"`
	Problems  map[string]string   `json:"problems"`
	CreatedAt int64               `json:"created_at"`
	Restored  bool                `json:"restored"`
}

func scriptBatchID(batch, device string) string {
	sum := sha256.Sum256([]byte("openrmm:script-batch:" + batch + ":" + device))
	return hex.EncodeToString(sum[:16])
}
func scriptBatchOwner(ctx context.Context, tx *sql.Tx, actor string) error {
	var owner string
	if e := tx.QueryRowContext(ctx, "SELECT username FROM administrators WHERE id=1").Scan(&owner); e != nil {
		return e
	}
	if owner != actor {
		return ErrForbidden
	}
	return nil
}
func batchChangeValid(c ScriptBatchChange) bool {
	if !protocol.ValidID(c.ID) || !protocol.ValidID(c.VersionID) || !validOrganizationName(c.Name) || len(c.Devices) > 25 || len(c.Groups) > 25 || len(c.Devices)+len(c.Groups) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range c.Devices {
		if !protocol.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, id := range c.Groups {
		if !ValidOrganizationID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func batchReady(ctx context.Context, tx *sql.Tx, id string, v ScriptVersion, now time.Time, offline time.Duration) (string, error) {
	var os, status, raw string
	var contact, reported int64
	var revoked *int64
	var busy bool
	e := tx.QueryRowContext(ctx, `SELECT d.os,COALESCE(d.last_contact_at,0),d.revoked_at,COALESCE(f.last_status,''),COALESCE(f.reported_at,0),COALESCE(f.support_json,''),EXISTS(SELECT 1 FROM script_runs r WHERE r.device_id=d.id AND r.status IN('queued','dispatched','running') AND r.expires_at>?) FROM devices d LEFT JOIN device_script_support f ON f.device_id=d.id WHERE d.id=?`, now.Unix(), id).Scan(&os, &contact, &revoked, &status, &reported, &raw, &busy)
	if e != nil {
		return "", e
	}
	if revoked != nil || os != "windows" {
		return "Active Windows device required", nil
	}
	if contact > now.Unix() || contact <= now.Add(-offline).Unix() {
		return "Device offline or contact unavailable", nil
	}
	var cap protocol.ScriptSupport
	if status != "ok" || reported > now.Unix() || reported <= now.Add(-2*time.Minute).Unix() || scripting.Decode([]byte(raw), &cap) != nil || !scripting.SupportValid(cap) {
		return "Fresh scripting support required", nil
	}
	if !cap.Restricted {
		return "Scripts are turned off on this device", nil
	}
	if v.Definition.RunAs == "system" && cap.Administrator != "enabled" {
		return "This device's agent cannot run SYSTEM scripts; update it", nil
	}
	if busy {
		return "Another script is pending or running", nil
	}
	return "", nil
}
func scanScriptBatch(ctx context.Context, tx *sql.Tx, id string) (ScriptBatch, error) {
	b := ScriptBatch{Problems: map[string]string{}}
	var change, targets, version string
	e := tx.QueryRowContext(ctx, "SELECT change_json,targets_json,version_id,actor,request_hash,created_at,restored FROM script_batches WHERE id=?", id).Scan(&change, &targets, &version, &b.Actor, &b.Digest, &b.CreatedAt, &b.Restored)
	if e != nil {
		return b, e
	}
	if json.Unmarshal([]byte(change), &b.Change) != nil || json.Unmarshal([]byte(targets), &b.Targets) != nil || b.Change.ID != id || b.Change.VersionID != version || !batchChangeValid(b.Change) || len(b.Targets) < 1 || len(b.Targets) > 25 {
		return b, ErrScriptBatch
	}
	b.Version, e = scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=?", version))
	if e != nil {
		return b, e
	}
	for i := range b.Targets {
		t := &b.Targets[i]
		if !protocol.ValidID(t.ID) || t.RunID != scriptBatchID(id, t.ID) {
			return b, ErrScriptBatch
		}
		e = tx.QueryRowContext(ctx, "SELECT status,cancel_requested FROM script_runs WHERE id=? AND device_id=?", t.RunID, t.ID).Scan(&t.Status, &t.CancelRequested)
		if errors.Is(e, sql.ErrNoRows) {
			t.Status = "history_unavailable"
		} else if e != nil {
			return b, e
		}
	}
	return b, nil
}

// Empty digest is a read-only review. Confirmation resolves the same selection
// in a transaction, then queues every existing script job or rolls back all.
func (s *Store) SubmitScriptBatch(ctx context.Context, c ScriptBatchChange, actor, digest string, now time.Time, offline time.Duration) (ScriptBatch, error) {
	b := ScriptBatch{Change: c, Actor: actor, Targets: []ScriptBatchTarget{}, Problems: map[string]string{}}
	if !batchChangeValid(c) || offline <= 0 {
		return b, ErrScriptBatch
	}
	c.Devices = append([]string{}, c.Devices...)
	c.Groups = append([]string{}, c.Groups...)
	sort.Strings(c.Devices)
	sort.Strings(c.Groups)
	b.Change = c
	rawChange, _ := json.Marshal(c)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return b, e
	}
	defer tx.Rollback()
	if e = scriptBatchOwner(ctx, tx, actor); e != nil {
		return b, e
	}
	// Check exact duplicates before current membership/readiness. An existing
	// batch is returned as history and can never queue replacement run IDs.
	if digest != "" {
		var saved, hash, owner string
		var restored bool
		e = tx.QueryRowContext(ctx, "SELECT change_json,request_hash,actor,restored FROM script_batches WHERE id=?", c.ID).Scan(&saved, &hash, &owner, &restored)
		if e == nil {
			if saved != string(rawChange) || hash != digest || owner != actor || restored {
				return b, ErrScriptBatch
			}
			old, err := scanScriptBatch(ctx, tx, c.ID)
			if err != nil {
				return b, err
			}
			return old, tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return b, e
		}
	}
	b.Version, e = scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=? AND id NOT IN(SELECT mutation_runner FROM application_versions UNION ALL SELECT verification_runner FROM application_versions)", c.VersionID))
	if e != nil || !scripting.ArgumentsValid(b.Version.Definition, c.Arguments) {
		return b, ErrScriptBatch
	}
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return b, e
	}
	selected, groups := map[string]bool{}, map[string]bool{}
	for _, id := range c.Devices {
		selected[id] = true
	}
	for _, id := range c.Groups {
		found := false
		for _, g := range o.Groups {
			if g.ID == id {
				found = true
			}
		}
		if !found {
			return b, ErrScriptBatch
		}
		groups[id] = true
	}
	matched := map[string]bool{}
	for _, d := range o.Devices {
		if selected[d.ID] || groups[d.GroupID] {
			b.Targets = append(b.Targets, ScriptBatchTarget{ID: d.ID, Hostname: d.Hostname, RunID: scriptBatchID(c.ID, d.ID)})
			matched[d.ID] = true
		}
	}
	for id := range selected {
		if !matched[id] {
			return b, ErrScriptBatch
		}
	}
	if len(b.Targets) == 0 || len(b.Targets) > 25 {
		return b, ErrScriptBatch
	}
	sort.Slice(b.Targets, func(i, j int) bool { return b.Targets[i].ID < b.Targets[j].ID })
	for _, t := range b.Targets {
		reason, err := batchReady(ctx, tx, t.ID, b.Version, now, offline)
		if err != nil {
			return b, err
		}
		if reason != "" {
			b.Problems[t.ID] = reason
		}
	}
	raw, _ := json.Marshal(struct {
		Change             ScriptBatchChange
		Targets            []ScriptBatchTarget
		VersionHash, Actor string
		Organization       int64
	}{c, b.Targets, b.Version.Hash, actor, o.Revision})
	sum := sha256.Sum256(raw)
	b.Digest = hex.EncodeToString(sum[:])
	if digest == "" {
		return b, nil
	}
	if digest != b.Digest || len(b.Problems) > 0 {
		return b, ErrScriptBatch
	}
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return b, e
	}
	// Keep records longer than confirmation lifetime, and never prune a batch
	// with active children. Run results retain their existing separate bounds.
	_, e = tx.ExecContext(ctx, `DELETE FROM script_batches WHERE created_at<? AND (created_at<? OR id IN(SELECT id FROM script_batches ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET 199)) AND NOT EXISTS(SELECT 1 FROM json_each(CASE WHEN json_valid(script_batches.targets_json) THEN script_batches.targets_json ELSE '[]' END) t JOIN script_runs r ON r.id=json_extract(t.value,'$.run_id') WHERE r.status IN('queued','dispatched','running'))`, now.Add(-5*time.Minute).Unix(), now.Add(-30*24*time.Hour).Unix())
	if e != nil {
		return b, e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM script_batches").Scan(&count); e != nil {
		return b, e
	}
	if count >= 200 {
		return b, ErrScriptBatch
	}
	targets, _ := json.Marshal(b.Targets)
	if _, e = tx.ExecContext(ctx, "INSERT INTO script_batches(id,version_id,name,actor,request_hash,change_json,targets_json,created_at)VALUES(?,?,?,?,?,?,?,?)", c.ID, c.VersionID, c.Name, actor, digest, string(rawChange), string(targets), now.Unix()); e != nil {
		return b, e
	}
	for _, t := range b.Targets {
		var exists int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM script_runs WHERE id=?", t.RunID).Scan(&exists); e != nil {
			return b, e
		}
		if exists != 0 {
			return b, ErrScriptBatch
		}
		run := ScriptRun{ScriptJob: protocol.ScriptJob{ID: t.RunID, Version: protocol.ScriptVersion{ID: c.VersionID}, Arguments: c.Arguments}, DeviceID: t.ID, Actor: actor}
		if e = queueScriptRun(ctx, tx, run, now, offline); e != nil {
			return b, e
		}
	}
	if e = auditDevice(ctx, tx, now, actor, "script_batch_requested", c.ID+":"+c.VersionID, "queued"); e != nil {
		return b, e
	}
	b.CreatedAt = now.Unix()
	return b, tx.Commit()
}

func (s *Store) ScriptBatch(ctx context.Context, id, actor string, now time.Time) (ScriptBatch, error) {
	if !protocol.ValidID(id) {
		return ScriptBatch{}, ErrScriptBatch
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ScriptBatch{}, e
	}
	defer tx.Rollback()
	if e = scriptBatchOwner(ctx, tx, actor); e != nil {
		return ScriptBatch{}, e
	}
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return ScriptBatch{}, e
	}
	b, e := scanScriptBatch(ctx, tx, id)
	if e != nil {
		return b, e
	}
	return b, tx.Commit()
}

type ScriptBatchSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Actor     string `json:"actor"`
	Script    string `json:"script"`
	Targets   int    `json:"targets"`
	CreatedAt int64  `json:"created_at"`
	Restored  bool   `json:"restored"`
}

func (s *Store) ScriptBatches(ctx context.Context, actor string) ([]ScriptBatchSummary, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = scriptBatchOwner(ctx, tx, actor); e != nil {
		return nil, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT b.id,b.name,b.actor,b.version_id,json_array_length(b.targets_json),b.created_at,b.restored FROM script_batches b ORDER BY b.created_at DESC,b.id DESC LIMIT 100`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ScriptBatchSummary{}
	for rows.Next() {
		var b ScriptBatchSummary
		if e = rows.Scan(&b.ID, &b.Name, &b.Actor, &b.Script, &b.Targets, &b.CreatedAt, &b.Restored); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) PruneScriptBatches(ctx context.Context, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `DELETE FROM script_batches WHERE created_at<? AND NOT EXISTS(SELECT 1 FROM json_each(CASE WHEN json_valid(script_batches.targets_json) THEN script_batches.targets_json ELSE '[]' END) t JOIN script_runs r ON r.id=json_extract(t.value,'$.run_id') WHERE r.status IN('queued','dispatched','running'))`, now.Add(-30*24*time.Hour).Unix())
	return e
}
