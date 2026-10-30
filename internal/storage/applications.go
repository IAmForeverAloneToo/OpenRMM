package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/applications"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

var ErrApplication = errors.New("application or targets changed/unavailable; reload and review again")

type ApplicationVersion struct {
	ID            string                  `json:"id"`
	ApplicationID string                  `json:"application_id"`
	Number        int                     `json:"number"`
	Definition    applications.Definition `json:"definition"`
	Mutation      protocol.ScriptVersion  `json:"mutation"`
	Verification  protocol.ScriptVersion  `json:"verification"`
	CreatedAt     int64                   `json:"created_at"`
	Actor         string                  `json:"actor"`
}
type ApplicationCatalog struct {
	Revision int64
	Versions []ApplicationVersion
}
type ApplicationChange struct {
	ID, ApplicationID string
	Revision          int64
	Definition        applications.Definition
}
type DeploymentChange struct {
	ID                string   `json:"id"`
	VersionID         string   `json:"version_id"`
	PreviousVersionID string   `json:"previous_version_id"`
	Operation         string   `json:"operation"`
	Devices           []string `json:"devices"`
	Groups            []string `json:"groups"`
}
type DeploymentTarget struct{ ID, Hostname string }
type DeploymentReview struct {
	Change   DeploymentChange
	Version  ApplicationVersion
	Previous *ApplicationVersion
	Targets  []DeploymentTarget
	Digest   string
}
type ApplicationDeployment struct {
	ID              string               `json:"id"`
	BatchID         string               `json:"batch_id"`
	DeviceID        string               `json:"device_id"`
	Hostname        string               `json:"hostname"`
	VersionID       string               `json:"version_id"`
	ApplicationID   string               `json:"application_id"`
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	ProductCode     string               `json:"product_code"`
	Operation       string               `json:"operation"`
	Actor           string               `json:"actor"`
	RunID           *string              `json:"run_id"`
	ExecutionStatus string               `json:"execution_status"`
	Status          string               `json:"status"`
	Reason          string               `json:"reason"`
	Report          *applications.Report `json:"report"`
	CreatedAt       int64                `json:"created_at"`
	DispatchedAt    *int64               `json:"dispatched_at"`
	FinishedAt      *int64               `json:"finished_at"`
}

func applicationID(domain, id string) string {
	s := sha256.Sum256([]byte("openrmm:application:" + domain + ":" + id))
	return hex.EncodeToString(s[:16])
}

// ownerTx requires the actor to be the primary administrator with confirmed
// MFA. Owner routes check this per session already; storage checks again
// inside the transaction that acts.
func ownerTx(ctx context.Context, tx *sql.Tx, actor string) error {
	var owner string
	e := tx.QueryRowContext(ctx, "SELECT username FROM administrators WHERE id=1 AND mfa_confirmed=1").Scan(&owner)
	if errors.Is(e, sql.ErrNoRows) || e == nil && owner != actor {
		return ErrForbidden
	}
	return e
}
func applicationVersionTx(ctx context.Context, tx *sql.Tx, id string) (ApplicationVersion, error) {
	var v ApplicationVersion
	var raw, mutation, verification string
	e := tx.QueryRowContext(ctx, "SELECT id,application_id,version,definition_json,mutation_runner,verification_runner,created_at,actor FROM application_versions WHERE id=?", id).Scan(&v.ID, &v.ApplicationID, &v.Number, &raw, &mutation, &verification, &v.CreatedAt, &v.Actor)
	if e != nil {
		return v, e
	}
	if json.Unmarshal([]byte(raw), &v.Definition) != nil || !applications.Valid(v.Definition) {
		return v, ErrApplication
	}
	m, e := scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=?", mutation))
	if e != nil {
		return v, e
	}
	q, e := scanScriptVersion(tx.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=?", verification))
	if e != nil {
		return v, e
	}
	if m.Definition.RunAs != "system" || q.Definition.RunAs != "restricted" {
		return v, ErrApplication
	}
	v.Mutation = m.ScriptVersion
	v.Verification = q.ScriptVersion
	return v, nil
}
func applicationVersionsTx(ctx context.Context, tx *sql.Tx, app string) ([]ApplicationVersion, error) {
	rows, e := tx.QueryContext(ctx, "SELECT id FROM application_versions WHERE (?='' OR application_id=?) ORDER BY created_at DESC,version DESC,id LIMIT 200", app, app)
	if e != nil {
		return nil, e
	}
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	items := []ApplicationVersion{}
	for _, id := range ids {
		v, e := applicationVersionTx(ctx, tx, id)
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, nil
}
func (s *Store) ApplicationCatalog(ctx context.Context) (ApplicationCatalog, error) {
	var c ApplicationCatalog
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return c, e
	}
	defer tx.Rollback()
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM application_state WHERE id=1").Scan(&c.Revision); e != nil {
		return c, e
	}
	c.Versions, e = applicationVersionsTx(ctx, tx, "")
	if e != nil {
		return c, e
	}
	return c, tx.Commit()
}
func (s *Store) ApplicationVersion(ctx context.Context, id string) (ApplicationVersion, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ApplicationVersion{}, e
	}
	defer tx.Rollback()
	v, e := applicationVersionTx(ctx, tx, id)
	if e != nil {
		return v, e
	}
	return v, tx.Commit()
}

func (s *Store) ChangeApplication(ctx context.Context, c ApplicationChange, actor, digest string, now time.Time) (ApplicationVersion, string, error) {
	var v ApplicationVersion
	if !protocol.ValidID(c.ID) || !protocol.ValidID(c.ApplicationID) || !applications.Valid(c.Definition) {
		return v, "", ErrApplication
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, "", e
	}
	defer tx.Rollback()
	if e = ownerTx(ctx, tx, actor); e != nil {
		return v, "", e
	}
	var revision int64
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM application_state WHERE id=1").Scan(&revision); e != nil {
		return v, "", e
	}
	if revision != c.Revision {
		return v, "", ErrApplication
	}
	var count, appCount, scriptCount, scriptFamilies, existing int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM application_versions").Scan(&count); e != nil {
		return v, "", e
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM applications").Scan(&appCount); e != nil {
		return v, "", e
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM applications WHERE id=?", c.ApplicationID).Scan(&existing); e != nil {
		return v, "", e
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COUNT(DISTINCT script_id) FROM script_versions").Scan(&scriptCount, &scriptFamilies); e != nil {
		return v, "", e
	}
	if count >= 200 || existing == 0 && (appCount >= 50 || scriptFamilies > maxScripts-2) || scriptCount > maxScriptVersions-2 {
		return v, "", ErrApplication
	}
	previous, e := applicationVersionsTx(ctx, tx, c.ApplicationID)
	if e != nil {
		return v, "", e
	}
	if len(previous) >= applications.MaxVersions {
		return v, "", ErrApplication
	}
	for _, p := range previous {
		if p.Definition.Version == c.Definition.Version || p.Definition.ProductCode == c.Definition.ProductCode {
			return v, "", ErrApplication
		}
	}
	var collision int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM application_versions WHERE id=? OR CASE WHEN json_valid(definition_json) THEN json_extract(definition_json,'$.product_code') END=?`, c.ID, c.Definition.ProductCode).Scan(&collision); e != nil {
		return v, "", e
	}
	if collision != 0 {
		return v, "", ErrApplication
	}
	v = ApplicationVersion{ID: c.ID, ApplicationID: c.ApplicationID, Number: len(previous) + 1, Definition: c.Definition, CreatedAt: now.Unix(), Actor: actor}
	for _, readonly := range []bool{false, true} {
		domain := "mutation"
		if readonly {
			domain = "verification"
		}
		q := protocol.ScriptVersion{ID: applicationID(domain, c.ID), ScriptID: applicationID(domain, c.ApplicationID), Number: v.Number, Definition: applications.Runner(c.Definition, readonly)}
		q.Hash = scripting.Digest(q)
		if !scripting.VersionValid(q) {
			return v, "", ErrApplication
		}
		if readonly {
			v.Verification = q
		} else {
			v.Mutation = q
		}
	}
	// Time is not part of a review: repeated reads must fingerprint identically.
	preview := v
	preview.CreatedAt = 0
	raw, _ := json.Marshal(struct {
		Change  ApplicationChange
		Version ApplicationVersion
	}{c, preview})
	sum := sha256.Sum256(raw)
	expected := hex.EncodeToString(sum[:])
	if digest == "" {
		return v, expected, nil
	}
	if digest != expected {
		return v, "", ErrApplication
	}
	if existing == 0 {
		if _, e = tx.ExecContext(ctx, "INSERT INTO applications(id,created_at) VALUES(?,?)", c.ApplicationID, now.Unix()); e != nil {
			return v, "", e
		}
	}
	for _, q := range []protocol.ScriptVersion{v.Mutation, v.Verification} {
		data, _ := json.Marshal(q.Definition)
		if _, e = tx.ExecContext(ctx, "INSERT INTO script_versions("+scriptVersionColumns+") VALUES(?,?,?,?,?,?,?)", q.ID, q.ScriptID, q.Number, q.Hash, string(data), now.Unix(), actor); e != nil {
			return v, "", e
		}
	}
	definition, _ := json.Marshal(c.Definition)
	if _, e = tx.ExecContext(ctx, "INSERT INTO application_versions(id,application_id,version,definition_json,mutation_runner,verification_runner,created_at,actor) VALUES(?,?,?,?,?,?,?,?)", v.ID, v.ApplicationID, v.Number, string(definition), v.Mutation.ID, v.Verification.ID, now.Unix(), actor); e != nil {
		return v, "", e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE application_state SET revision=revision+1 WHERE id=1"); e != nil {
		return v, "", e
	}
	if e = auditDevice(ctx, tx, now, actor, "application_version_created", v.ApplicationID+":"+v.ID+":"+v.Definition.SHA256, "immutable"); e != nil {
		return v, "", e
	}
	return v, expected, tx.Commit()
}

func deploymentReviewTx(ctx context.Context, tx *sql.Tx, c DeploymentChange, actor string) (DeploymentReview, error) {
	r := DeploymentReview{Change: c}
	if !protocol.ValidID(c.ID) || !protocol.ValidID(c.VersionID) || !applications.Operation(c.Operation) || len(c.Devices) > applications.MaxTargets || len(c.Groups) > 25 || len(c.Devices)+len(c.Groups) == 0 {
		return r, ErrApplication
	}
	if e := ownerTx(ctx, tx, actor); e != nil {
		return r, e
	}
	v, e := applicationVersionTx(ctx, tx, c.VersionID)
	if e != nil {
		return r, e
	}
	r.Version = v
	if c.Operation == "update" {
		p, e := applicationVersionTx(ctx, tx, c.PreviousVersionID)
		if e != nil {
			return r, e
		}
		if p.ApplicationID != v.ApplicationID || p.ID == v.ID || !applications.Newer(v.Definition.Version, p.Definition.Version) || p.Definition.ProductCode == v.Definition.ProductCode {
			return r, ErrApplication
		}
		r.Previous = &p
	} else if c.PreviousVersionID != "" {
		return r, ErrApplication
	}
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return r, e
	}
	devices, groups := map[string]bool{}, map[string]bool{}
	for _, id := range c.Devices {
		if !protocol.ValidID(id) || devices[id] {
			return r, ErrApplication
		}
		devices[id] = true
	}
	for _, id := range c.Groups {
		if !ValidOrganizationID(id) || groups[id] {
			return r, ErrApplication
		}
		exists := false
		for _, g := range o.Groups {
			if g.ID == id {
				exists = true
			}
		}
		if !exists {
			return r, ErrApplication
		}
		groups[id] = true
	}
	matched := map[string]bool{}
	for _, d := range o.Devices {
		if !devices[d.ID] && !groups[d.GroupID] {
			continue
		}
		var osName string
		if e = tx.QueryRowContext(ctx, "SELECT os FROM devices WHERE id=? AND revoked_at IS NULL", d.ID).Scan(&osName); e != nil {
			return r, e
		}
		if osName != "windows" {
			return r, ErrApplication
		}
		r.Targets = append(r.Targets, DeploymentTarget{d.ID, d.Hostname})
		matched[d.ID] = true
	}
	for id := range devices {
		if !matched[id] {
			return r, ErrApplication
		}
	}
	if len(r.Targets) == 0 || len(r.Targets) > applications.MaxTargets {
		return r, ErrApplication
	}
	sort.Slice(r.Targets, func(i, j int) bool { return r.Targets[i].ID < r.Targets[j].ID })
	var revision int64
	if e = tx.QueryRowContext(ctx, "SELECT revision FROM application_state WHERE id=1").Scan(&revision); e != nil {
		return r, e
	}
	raw, _ := json.Marshal(struct {
		Review                 DeploymentReview
		Revision, Organization int64
		Actor                  string
	}{r, revision, o.Revision, actor})
	sum := sha256.Sum256(raw)
	r.Digest = hex.EncodeToString(sum[:])
	return r, nil
}

func (s *Store) DeployApplication(ctx context.Context, c DeploymentChange, actor, digest string, now time.Time, offline time.Duration) (DeploymentReview, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return DeploymentReview{}, e
	}
	defer tx.Rollback()
	r, e := deploymentReviewTx(ctx, tx, c, actor)
	if e != nil {
		return r, e
	}
	if digest == "" {
		return r, nil
	}
	if digest != r.Digest {
		return r, ErrApplication
	}
	var duplicate int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM application_deployments WHERE batch_id=?", c.ID).Scan(&duplicate); e != nil {
		return r, e
	}
	if duplicate > 0 {
		var matching int
		if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM application_deployments WHERE batch_id=? AND request_hash=? AND actor=?", c.ID, digest, actor).Scan(&matching); e != nil {
			return r, e
		}
		if matching != len(r.Targets) || duplicate != matching {
			return r, ErrApplication
		}
		return r, tx.Commit()
	}
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return r, e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM application_deployments WHERE status NOT IN ('queued','dispatched','running') AND (created_at<? OR id IN (SELECT id FROM application_deployments ORDER BY created_at DESC,id LIMIT -1 OFFSET 1975))`, now.Add(-30*24*time.Hour).Unix()); e != nil {
		return r, e
	}
	var count int
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM application_deployments").Scan(&count); e != nil {
		return r, e
	}
	if count+len(r.Targets) > 2000 {
		return r, ErrApplication
	}
	versions, e := applicationVersionsTx(ctx, tx, r.Version.ApplicationID)
	if e != nil {
		return r, e
	}
	codes := []string{}
	for _, v := range versions {
		codes = append(codes, v.Definition.ProductCode)
	}
	sort.Strings(codes)
	known, _ := json.Marshal(codes)
	for _, d := range r.Targets {
		id := applicationID(d.ID, c.ID)
		runner := r.Version.Mutation
		if c.Operation == "verify" {
			runner = r.Version.Verification
		}
		args := map[string]string{"Operation": c.Operation, "KnownProducts": string(known)}
		var previous any
		if r.Previous != nil {
			previous = r.Previous.ID
			args["PreviousCode"] = r.Previous.Definition.ProductCode
			args["PreviousVersion"] = r.Previous.Definition.Version
		}
		job := ScriptRun{ScriptJob: protocol.ScriptJob{ID: id, Version: runner, Arguments: args}, DeviceID: d.ID, Actor: actor}
		if e = queueScriptRun(ctx, tx, job, now, offline); e != nil {
			return r, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO application_deployments(id,batch_id,device_id,version_id,previous_version_id,operation,actor,request_hash,known_products_json,run_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, c.ID, d.ID, c.VersionID, previous, c.Operation, actor, digest, string(known), id, now.Unix()); e != nil {
			return r, e
		}
		if e = auditDevice(ctx, tx, now, actor, "application_deployment_queued", d.ID+":"+id+":"+c.VersionID, c.Operation); e != nil {
			return r, e
		}
	}
	return r, tx.Commit()
}

// Read models contain package identity, never the owner-only source URL or code.
func (s *Store) ApplicationDeployments(ctx context.Context, v Session, device string, now time.Time) ([]ApplicationDeployment, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if e = expireScriptRuns(ctx, tx, now); e != nil {
		return nil, e
	}
	scope, args := technicianScope(v, "a.device_id")
	args = append([]any{device, device}, args...)
	rows, e := tx.QueryContext(ctx, `SELECT a.id,a.batch_id,a.device_id,d.hostname,a.version_id,p.application_id,p.definition_json,a.operation,a.actor,a.run_id,a.status,a.result_json,a.known_products_json,a.created_at,a.dispatched_at,a.finished_at FROM application_deployments a JOIN devices d ON d.id=a.device_id JOIN application_versions p ON p.id=a.version_id WHERE (?='' OR a.device_id=?) AND `+scope+` ORDER BY a.created_at DESC,a.id DESC LIMIT 200`, args...)
	if e != nil {
		return nil, e
	}
	items := []ApplicationDeployment{}
	for rows.Next() {
		var a ApplicationDeployment
		var definition, raw, known string
		if e = rows.Scan(&a.ID, &a.BatchID, &a.DeviceID, &a.Hostname, &a.VersionID, &a.ApplicationID, &definition, &a.Operation, &a.Actor, &a.RunID, &a.ExecutionStatus, &raw, &known, &a.CreatedAt, &a.DispatchedAt, &a.FinishedAt); e != nil {
			rows.Close()
			return nil, e
		}
		var def applications.Definition
		if json.Unmarshal([]byte(definition), &def) != nil {
			rows.Close()
			return nil, ErrApplication
		}
		a.Name = def.Name
		a.Version = def.Version
		a.ProductCode = def.ProductCode
		a.Status = a.ExecutionStatus
		a.Reason = ""
		if a.ExecutionStatus != "queued" && a.ExecutionStatus != "dispatched" && a.ExecutionStatus != "running" {
			a.Status = "unknown"
			a.Reason = "execution_uncertain"
			if (a.ExecutionStatus == "expired" || a.ExecutionStatus == "cancelled") && a.DispatchedAt == nil {
				a.Status = "cancelled"
				a.Reason = "not_executed"
			}
			var result protocol.ScriptResult
			var report applications.Report
			if raw != "" && scripting.Decode([]byte(raw), &result) == nil && result.ID == a.ID && scripting.ResultValid(result) && result.Outcome == "succeeded" && !result.Truncated && scripting.Decode([]byte(strings.TrimSpace(result.Stdout)), &report) == nil && applications.ReportValid(report) && report.Operation == a.Operation && applications.PostconditionValid(def, report) {
				var codes []string
				if json.Unmarshal([]byte(known), &codes) != nil {
					rows.Close()
					return nil, ErrApplication
				}
				allowed := map[string]bool{}
				for _, code := range codes {
					allowed[code] = true
				}
				valid := true
				for _, product := range report.Products {
					if !allowed[product.Code] {
						valid = false
					}
				}
				if !valid {
					items = append(items, a)
					continue
				}
				a.Status = report.Outcome
				a.Reason = report.Reason
				a.Report = &report
			}
		}
		items = append(items, a)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	return items, tx.Commit()
}

func (s *Store) CancelApplicationDeployment(ctx context.Context, id, actor string, now time.Time) error {
	var device string
	var run *string
	if !protocol.ValidID(id) {
		return ErrApplication
	}
	// The owner check, the lookup and the cancel are one transaction.
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = ownerTx(ctx, tx, actor); e != nil {
		return e
	}
	e = tx.QueryRowContext(ctx, "SELECT device_id,run_id FROM application_deployments WHERE id=?", id).Scan(&device, &run)
	if e != nil || run == nil {
		return ErrApplication
	}
	if e = cancelScriptRunTx(ctx, tx, device, *run, actor, now); e != nil {
		return e
	}
	return tx.Commit()
}
