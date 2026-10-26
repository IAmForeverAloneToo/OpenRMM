package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// openFile opens a database file directly, without migrating it, for the
// backup tools in the updater.
func openFile(path string, readOnly bool) (*sql.DB, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("invalid database path")
	}
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := &url.URL{Scheme: "file", Path: uriPath}
	query := uri.Query()
	// Never create a database that does not exist.
	query.Set("mode", "rw")
	if readOnly {
		query.Set("mode", "ro")
	}
	query.Add("_pragma", "busy_timeout(10000)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, errors.New("cannot open the database")
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// SnapshotFile writes a consistent copy of a database that the server may
// be using at the same time (SQLite's VACUUM INTO). The copy has no WAL.
func SnapshotFile(ctx context.Context, src, dst string) error {
	db, err := openFile(src, false)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err = db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return errors.New("cannot copy the live database")
	}
	return nil
}

// InspectFile returns a database file's installation ID and schema version
// without changing it.
func InspectFile(ctx context.Context, path string) (Info, error) {
	db, err := openFile(path, true)
	if err != nil {
		return Info{}, err
	}
	defer db.Close()
	var info Info
	if err = db.QueryRowContext(ctx, "SELECT instance_id, created_at FROM server_state WHERE id = 1").Scan(&info.InstanceID, &info.CreatedAt); err != nil {
		return Info{}, errors.New("cannot read the installation of the database")
	}
	if err = db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&info.SchemaVersion); err != nil {
		return Info{}, errors.New("cannot read the schema version of the database")
	}
	return info, nil
}

// RevokedDevicesFile lists the revoked devices recorded in a database file
// (device ID → revocation time), so a restore can carry them over.
func RevokedDevicesFile(ctx context.Context, path string) (map[string]int64, error) {
	db, err := openFile(path, true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT id, revoked_at FROM devices WHERE revoked_at IS NOT NULL")
	if err != nil {
		return nil, errors.New("cannot read the revoked devices")
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var at int64
		if err = rows.Scan(&id, &at); err != nil {
			return nil, errors.New("cannot read the revoked devices")
		}
		out[id] = at
	}
	if rows.Err() != nil {
		return nil, errors.New("cannot read the revoked devices")
	}
	return out, nil
}

// ReconcileRestore prepares a restored database so that nothing from the
// older snapshot is replayed against devices and no old credential becomes
// usable again: revocations are applied, sessions and one-time secrets are
// removed, queued work is cancelled and work in flight becomes unknown. The
// database is migrated to this build's schema first.
func ReconcileRestore(ctx context.Context, path string, revoked map[string]int64, now time.Time) error {
	for id, at := range revoked {
		if !protocol.ValidID(id) || at <= 0 {
			return errors.New("the revocation list is invalid")
		}
	}
	s, err := Open(ctx, path)
	if err != nil {
		return err
	}
	defer s.Close()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("cannot begin the restore changes")
	}
	defer tx.Rollback()
	for id, at := range revoked {
		if _, err = tx.ExecContext(ctx, "UPDATE devices SET revoked_at=COALESCE(revoked_at,?) WHERE id=?", at, id); err != nil {
			return errors.New("cannot apply the revocations")
		}
	}
	t, step := now.Unix(), now.Unix()/30
	for i, q := range []struct {
		sql  string
		args []any
	}{
		// Patching, schedules and agent updates never resume on their own.
		{"UPDATE patch_policies SET state='paused',revision=revision+1,updated_at=? WHERE state IN('active','paused')", []any{t}},
		{"UPDATE patch_device_guards SET hold='needs_review',revision=revision+1 WHERE hold='mutation_running'", nil},
		{"UPDATE patch_runs SET status='unknown',detail='server_restore',finished_at=? WHERE finished_at IS NULL", []any{t}},
		{"UPDATE script_schedules SET state='paused',revision=revision+1,updated_at=? WHERE state IN('active','paused')", []any{t}},
		{"DELETE FROM script_schedule_occurrences", nil},
		{"UPDATE agent_upgrade_jobs SET status=CASE WHEN status='queued' THEN 'cancelled' WHEN status='dispatched' THEN 'unknown' ELSE status END,result_json='',finished_at=COALESCE(finished_at,?)", []any{t}},
		{"UPDATE device_agent_upgrade_support SET last_status='failed',support_json=''", nil},
		// A restored evidence collection (including hunts, triage, live
		// response and isolation steps) is never resumed or dispatched again.
		{"UPDATE evidence_jobs SET status='failed',outcome='server_restore',finished_at=? WHERE status IN('queued','dispatched','uploading','verifying')", []any{t}},
		{"DELETE FROM evidence_chunks", nil},
		{"UPDATE file_jobs SET status=CASE WHEN status IN('staged','queued') THEN 'cancelled' WHEN status='dispatched' THEN 'unknown' ELSE status END,payload=X'',reserve_bytes=0,result_json='',payload_until=0,finished_at=COALESCE(finished_at,?)", []any{t}},
		{"UPDATE device_file_support SET last_status='failed',support_json=''", nil},
		{"UPDATE application_deployments SET status=CASE WHEN status='queued' THEN 'cancelled' WHEN status IN('dispatched','running') THEN 'unknown' ELSE status END,result_json='',finished_at=COALESCE(finished_at,?)", []any{t}},
		{"UPDATE script_runs SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'unknown' END,finished_at=?,result_json='' WHERE status IN('queued','dispatched','running')", []any{t}},
		{"UPDATE script_runs SET result_json=''", nil},
		{"UPDATE device_script_support SET last_status='failed',support_json=''", nil},
		{"UPDATE script_batches SET restored=1", nil},
		{"UPDATE device_processes SET last_status='failed'", nil},
		{"UPDATE process_actions SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", []any{t}},
		{"DELETE FROM software_changes", nil},
		{"UPDATE device_software SET baseline_ready=0,last_status='failed'", nil},
		// Alerts: nothing is sent for the old state, and e-mail stays paused
		// until an administrator resumes it.
		{"DELETE FROM alert_deliveries", nil},
		{"DELETE FROM alert_samples", nil},
		{"UPDATE alert_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.value',NULL)", nil},
		{"UPDATE alert_runtime SET mail_paused=1,last_sweep=0,mail_config='',gap=0", nil},
		{"UPDATE update_jobs SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", []any{t}},
		{"UPDATE health_checks SET response=0,revision=revision+1", nil},
		{"DELETE FROM health_samples", nil},
		{"UPDATE health_states SET state_json=json_set(state_json,'$.condition','unknown','$.since',0,'$.samples',0,'$.last_sample',0)", nil},
		{"UPDATE service_actions SET status=CASE WHEN status='dispatched' THEN 'unknown' ELSE 'cancelled' END,finished_at=? WHERE status IN ('queued','dispatched')", []any{t}},
		{"DELETE FROM event_log_queries", nil},
		// Credentials: no session, invitation, recovery code, current
		// authenticator step or superseded device certificate comes back.
		{"UPDATE technicians SET enabled=0,revision=revision+1,invitation_hash=NULL,invitation_until=NULL,last_totp_step=MAX(last_totp_step,?)", []any{step}},
		{"DELETE FROM technician_recovery_codes", nil},
		{"DELETE FROM sessions", nil},
		{"DELETE FROM enrollment_tokens", nil},
		{"DELETE FROM recovery_codes", nil},
		{"UPDATE administrators SET last_totp_step=MAX(last_totp_step,?)", []any{step}},
		{"UPDATE devices SET previous_fingerprint='',previous_until=0", nil},
	} {
		if _, err = tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return fmt.Errorf("cannot apply the restore changes (step %d)", i+1)
		}
	}
	if err = audit(ctx, tx, now, "backup_restore", "restore_reconciled", "success"); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.New("cannot store the restore changes")
	}
	return nil
}
