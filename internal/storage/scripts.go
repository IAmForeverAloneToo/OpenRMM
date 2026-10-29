package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"time"
)

var ErrScript = errors.New("script operation unavailable; refresh and check version, device state, local permissions and active runs")

type ScriptVersion struct {
	protocol.ScriptVersion
	CreatedAt int64  `json:"created_at"`
	Actor     string `json:"actor"`
}

func scanScriptVersion(row interface{ Scan(...any) error }) (ScriptVersion, error) {
	var v ScriptVersion
	var data string
	e := row.Scan(&v.ID, &v.ScriptID, &v.Number, &v.Hash, &data, &v.CreatedAt, &v.Actor)
	if e != nil {
		return v, e
	}
	if scripting.Decode([]byte(data), &v.Definition) != nil || !scripting.VersionValid(v.ScriptVersion) {
		return v, ErrScript
	}
	return v, nil
}

const scriptVersionColumns = "id,script_id,version,sha256,definition_json,created_at,actor"

// A script keeps its newest keptScriptVersions versions, and older ones only
// while a run, schedule, batch or application uses them.
const (
	maxScripts         = 1000
	keptScriptVersions = 10
	maxScriptVersions  = 15000
	usedScriptVersions = "SELECT version_id FROM script_runs UNION SELECT version_id FROM script_schedules UNION SELECT version_id FROM script_batches UNION SELECT mutation_runner FROM application_versions UNION SELECT verification_runner FROM application_versions"
)

func (s *Store) CreateScriptVersion(ctx context.Context, v ScriptVersion, now time.Time) (ScriptVersion, error) {
	if !protocol.ValidID(v.ID) || !protocol.ValidID(v.ScriptID) || !scripting.DefinitionValid(v.Definition) || v.Actor == "" || !scripting.Text(v.Actor, 128, false) {
		return v, ErrScript
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	var managed int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM application_versions a JOIN script_versions q ON q.id IN(a.mutation_runner,a.verification_runner) WHERE q.script_id=?`, v.ScriptID).Scan(&managed); e != nil {
		return v, e
	}
	if managed > 0 {
		return v, ErrScript
	}
	var total, scripts, number int
	if e = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0) FROM script_versions WHERE script_id=?", v.ScriptID).Scan(&number); e != nil {
		return v, e
	}
	// Older versions nothing uses any more make room for the new one.
	if _, e = tx.ExecContext(ctx, "DELETE FROM script_versions WHERE script_id=? AND version<=? AND id NOT IN ("+usedScriptVersions+")", v.ScriptID, number-keptScriptVersions+1); e != nil {
		return v, e
	}
	if e = tx.QueryRowContext(ctx, "SELECT COUNT(*),COUNT(DISTINCT script_id) FROM script_versions").Scan(&total, &scripts); e != nil {
		return v, e
	}
	if total >= maxScriptVersions || number == 0 && scripts >= maxScripts {
		return v, ErrScript
	}
	v.Number = number + 1
	v.Hash = scripting.Digest(v.ScriptVersion)
	v.CreatedAt = now.Unix()
	data, _ := json.Marshal(v.Definition)
	if _, e = tx.ExecContext(ctx, "INSERT INTO script_versions("+scriptVersionColumns+") VALUES(?,?,?,?,?,?,?)", v.ID, v.ScriptID, v.Number, v.Hash, string(data), v.CreatedAt, v.Actor); e != nil {
		return v, ErrScript
	}
	if e = auditDevice(ctx, tx, now, v.Actor, "script_version_created", v.ScriptID+":"+v.ID+":"+v.Hash, "created"); e != nil {
		return v, e
	}
	return v, tx.Commit()
}
func (s *Store) ScriptVersion(ctx context.Context, id string) (ScriptVersion, error) {
	v, e := scanScriptVersion(s.db.QueryRowContext(ctx, "SELECT "+scriptVersionColumns+" FROM script_versions WHERE id=? AND id NOT IN(SELECT mutation_runner FROM application_versions UNION ALL SELECT verification_runner FROM application_versions)", id))
	if errors.Is(e, sql.ErrNoRows) {
		return v, ErrScript
	}
	return v, e
}

// ScriptNamed finds the newest version of the library script with a name
// (case-insensitive), for the live response run command.
func (s *Store) ScriptNamed(ctx context.Context, name string) (string, error) {
	var id string
	e := s.db.QueryRowContext(ctx, "SELECT id FROM script_versions WHERE lower(json_extract(definition_json,'$.name'))=lower(?) AND version=(SELECT MAX(v.version) FROM script_versions v WHERE v.script_id=script_versions.script_id) AND id NOT IN(SELECT mutation_runner FROM application_versions UNION ALL SELECT verification_runner FROM application_versions) ORDER BY created_at DESC,id LIMIT 1", name).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return "", ErrScript
	}
	return id, e
}

func (s *Store) ScriptVersions(ctx context.Context, scriptID string) ([]ScriptVersion, error) {
	hide := " AND id NOT IN(SELECT mutation_runner FROM application_versions UNION ALL SELECT verification_runner FROM application_versions)"
	query := "SELECT " + scriptVersionColumns + " FROM script_versions WHERE version=(SELECT MAX(v.version) FROM script_versions v WHERE v.script_id=script_versions.script_id)" + hide + " ORDER BY created_at DESC,id LIMIT 100"
	args := []any{}
	if scriptID != "" {
		query = "SELECT " + scriptVersionColumns + " FROM script_versions WHERE script_id=?" + hide + " ORDER BY version DESC LIMIT 500"
		args = append(args, scriptID)
	}
	rows, e := s.db.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	items := []ScriptVersion{}
	for rows.Next() {
		v, e := scanScriptVersion(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

type ScriptSupport struct {
	Status     string                 `json:"status"`
	ReportedAt int64                  `json:"reported_at"`
	Support    protocol.ScriptSupport `json:"support"`
}

func (s *Store) RecordScriptSupport(ctx context.Context, id, fp string, r protocol.FeatureReport, now time.Time) error {
	r, e := scripting.Normalize(r)
	if e != nil {
		return e
	}
	result, e := s.db.ExecContext(ctx, `INSERT INTO device_script_support(device_id,capability_version,last_status,reported_at,support_json) SELECT id,?,?,?,? FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR(previous_fingerprint=? AND previous_until>?)) ON CONFLICT(device_id) DO UPDATE SET capability_version=excluded.capability_version,last_status=excluded.last_status,reported_at=excluded.reported_at,support_json=excluded.support_json WHERE excluded.reported_at>=device_script_support.reported_at`, r.Capability.Version, r.Status, now.Unix(), string(r.Data), id, fp, fp, now.Unix())
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		var found string
		e = s.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE id=? AND revoked_at IS NULL AND (fingerprint=? OR(previous_fingerprint=? AND previous_until>?))`, id, fp, fp, now.Unix()).Scan(&found)
		if errors.Is(e, sql.ErrNoRows) {
			return ErrAuthentication
		}
		return e
	}
	return nil
}
func (s *Store) ScriptSupport(ctx context.Context, id string) (ScriptSupport, error) {
	v := ScriptSupport{Status: "not_reported"}
	var raw string
	e := s.db.QueryRowContext(ctx, "SELECT last_status,reported_at,support_json FROM device_script_support WHERE device_id=?", id).Scan(&v.Status, &v.ReportedAt, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	if v.Status == "ok" && (scripting.Decode([]byte(raw), &v.Support) != nil || !scripting.SupportValid(v.Support)) {
		return v, ErrScript
	}
	return v, nil
}
