package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

// The response tool library and the server's side of response
// scripts and file drops.

// ErrTool covers unknown or withdrawn tools, invalid names and the quota.
var ErrTool = errors.New("tool unavailable; check the name, size, quota and that the tool is not withdrawn")

type ResponseTool struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Actor       string `json:"actor"`
	CreatedAt   int64  `json:"created_at"`
	WithdrawnAt *int64 `json:"withdrawn_at"`
}

func toolName(s string) bool {
	return validText(s, 255, false) && !strings.ContainsAny(s, `\/:<>"|?*`) && s != "." && s != ".."
}

// AddTool stores an uploaded tool by its SHA-256 in the evidence store,
// within the evidence quota.
// sizeHint (the request's length, or -1) lets an upload that cannot fit the
// quota be refused before it is written.
func (s *Store) AddTool(ctx context.Context, name, description, actor string, body io.Reader, sizeHint int64, now time.Time) (ResponseTool, error) {
	t := ResponseTool{Name: name, Description: description, Actor: actor, CreatedAt: now.Unix()}
	if s.evidence == "" || !toolName(name) || description != "" && !validText(description, 2000, true) {
		return t, ErrTool
	}
	if s.evidenceQuota > 0 && sizeHint > 0 {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return t, e
		}
		used, e := s.quotaUsed(ctx, tx)
		tx.Rollback()
		if e != nil {
			return t, e
		}
		if used+sizeHint-64*1024 > s.evidenceQuota {
			return t, ErrTool
		}
	}
	id, e := evidenceID()
	if e != nil {
		return t, e
	}
	t.ID = id
	temp := s.incoming("tool-" + id)
	f, e := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return t, errors.New("cannot store the tool")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, protocol.MaxDrop+1))
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	defer os.Remove(temp)
	if e != nil {
		return t, errors.New("cannot store the tool")
	}
	if n > protocol.MaxDrop {
		return t, ErrTool
	}
	t.SHA256, t.Size = hex.EncodeToString(h.Sum(nil)), n
	// Content already in the store is checked before the transaction: hashing
	// up to 4 GiB must not hold the single database connection.
	target := s.stored(t.SHA256)
	stored, size, hashErr := hashFile(ctx, target)
	present := hashErr == nil && stored == t.SHA256 && size == n
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return t, e
	}
	defer tx.Rollback()
	used, e := s.quotaUsed(ctx, tx)
	if e != nil {
		return t, e
	}
	var held int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_files WHERE sha256=?`, t.SHA256).Scan(&held); e != nil {
		return t, e
	}
	if held == 0 && s.evidenceQuota > 0 && used+n > s.evidenceQuota {
		return t, ErrTool
	}
	if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
		return t, e
	}
	if !present {
		_ = os.Chmod(target, 0600)
		if e = os.Rename(temp, target); e != nil {
			return t, errors.New("cannot store the tool")
		}
	}
	_ = os.Chmod(target, 0400)
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO evidence_files(sha256,size,stored_at) VALUES(?,?,?)`, t.SHA256, n, now.Unix()); e != nil {
		return t, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO response_tools(id,name,description,sha256,size,actor,created_at) VALUES(?,?,?,?,?,?,?)`, t.ID, t.Name, t.Description, t.SHA256, t.Size, actor, t.CreatedAt); e != nil {
		return t, e
	}
	if e = auditDevice(ctx, tx, now, actor, "response_tool_added", t.ID+":"+t.SHA256, "added"); e != nil {
		return t, e
	}
	return t, tx.Commit()
}

// Tools lists the tool library, newest first.
func (s *Store) Tools(ctx context.Context) ([]ResponseTool, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT id,name,description,sha256,size,actor,created_at,withdrawn_at FROM response_tools ORDER BY created_at DESC,id LIMIT 500`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ResponseTool{}
	for rows.Next() {
		var t ResponseTool
		if e = rows.Scan(&t.ID, &t.Name, &t.Description, &t.SHA256, &t.Size, &t.Actor, &t.CreatedAt, &t.WithdrawnAt); e != nil {
			return nil, e
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// WithdrawTool stops a tool from being dropped; its file stays.
func (s *Store) WithdrawTool(ctx context.Context, id, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE response_tools SET withdrawn_at=? WHERE id=? AND withdrawn_at IS NULL`, now.Unix(), id)
	if e != nil {
		return e
	}
	if n, e := r.RowsAffected(); e != nil || n != 1 {
		return ErrTool
	}
	if e = auditDevice(ctx, tx, now, actor, "response_tool_withdrawn", id, "withdrawn"); e != nil {
		return e
	}
	return tx.Commit()
}

// ResolveAction completes a case action from what the server holds: a
// library script's body, parameters and timeout (by script version), and a
// dropped file's name, hash and size (from the tool library or the case's
// evidence). The result is what the device receives and the custody log
// records.
func (s *Store) ResolveAction(ctx context.Context, caseID string, a protocol.ResponseAction) (protocol.ResponseAction, error) {
	if len(a.Arguments) == 0 {
		a.Arguments = nil
	}
	switch a.Kind {
	case "script":
		if a.Ref != "" {
			v, e := s.ScriptVersion(ctx, a.Ref)
			if e != nil {
				return a, ErrEvidence
			}
			d := v.Definition
			a.Name, a.Script, a.Parameters, a.Timeout = d.Name, d.Body, d.Parameters, d.Timeout
			if len(a.Parameters) == 0 {
				a.Parameters = nil
			}
		} else if a.Name == "" {
			a.Name = "Case script"
		}
		if a.Timeout == 0 {
			a.Timeout = 60
		}
		if _, ok := scripting.ResponseJob(strings.Repeat("0", 32), a, 1); !ok {
			return a, ErrEvidence
		}
	case "drop":
		if !protocol.ValidID(a.Ref) {
			return a, ErrEvidence
		}
		var e error
		switch a.Source {
		case "tool":
			e = s.db.QueryRowContext(ctx, `SELECT name,sha256,size FROM response_tools WHERE id=? AND withdrawn_at IS NULL`, a.Ref).Scan(&a.Name, &a.SHA256, &a.Size)
		case "evidence":
			var j EvidenceJob
			e = s.db.QueryRowContext(ctx, `SELECT id,path,source,kind,action,server_sha256,size FROM evidence_jobs WHERE id=? AND case_id=? AND status='succeeded'`, a.Ref, caseID).Scan(&j.ID, &j.Path, &j.Source, &j.Kind, &j.Action, &j.ServerSHA256, &j.Size)
			a.Name, a.SHA256, a.Size = j.Name(), j.ServerSHA256, j.Size
		default:
			e = ErrEvidence
		}
		if errors.Is(e, sql.ErrNoRows) || e != nil {
			return a, ErrEvidence
		}
	}
	if !a.Valid() {
		return a, ErrEvidence
	}
	return a, nil
}

// DropPayload opens the file a drop action sends to its device, after
// device authentication; the agent may fetch it while the job runs.
func (s *Store) DropPayload(ctx context.Context, device, fp, job string, now time.Time) (*os.File, int64, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, 0, e
	}
	j, e := deviceJob(ctx, tx, device, fp, job, now)
	spec := ""
	if e == nil {
		e = tx.QueryRowContext(ctx, `SELECT action FROM evidence_jobs WHERE id=?`, job).Scan(&spec)
	}
	tx.Rollback()
	if e != nil {
		return nil, 0, ErrEvidence
	}
	a, ok := protocol.ParseAction(spec)
	if !ok || a.Kind != "drop" || j.Status != "dispatched" && j.Status != "uploading" {
		return nil, 0, ErrEvidence
	}
	// Withdrawing a tool also stops drops already handed out.
	if a.Source == "tool" {
		var withdrawn int
		if e = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM response_tools WHERE id=? AND withdrawn_at IS NOT NULL`, a.Ref).Scan(&withdrawn); e != nil || withdrawn > 0 {
			return nil, 0, ErrEvidence
		}
	}
	f, e := os.Open(s.stored(a.SHA256))
	if e != nil {
		return nil, 0, errors.New("the file is missing from the evidence store")
	}
	if i, e := f.Stat(); e != nil || i.Size() != a.Size {
		f.Close()
		return nil, 0, errors.New("the stored file does not have its recorded size")
	}
	return f, a.Size, nil
}

// ToolNamed finds the library tool with a name (the newest one that is not
// withdrawn), for the live response put command.
func (s *Store) ToolNamed(ctx context.Context, name string) (string, error) {
	var id string
	e := s.db.QueryRowContext(ctx, `SELECT id FROM response_tools WHERE lower(name)=lower(?) AND withdrawn_at IS NULL ORDER BY created_at DESC,id LIMIT 1`, name).Scan(&id)
	if e != nil {
		return "", ErrTool
	}
	return id, nil
}

// ListedProcess finds a process in the device's most recent process list
// from the last 30 minutes (live response kill): its start time
// and name make the kill refuse a reused PID.
func (s *Store) ListedProcess(ctx context.Context, device string, pid uint32, now time.Time) (start, name string, err error) {
	var job, caseID, hash string
	e := s.db.QueryRowContext(ctx, `SELECT id,case_id,server_sha256 FROM evidence_jobs WHERE device_id=? AND status='succeeded' AND action LIKE '{"kind":"processes"%' AND finished_at>=? ORDER BY finished_at DESC,id LIMIT 1`, device, now.Add(-30*time.Minute).Unix()).Scan(&job, &caseID, &hash)
	if e != nil {
		return "", "", ErrEvidence
	}
	path := s.stored(hash)
	if caseID == LiveCase {
		path = s.scratch(job)
	}
	b, e := os.ReadFile(path)
	var r protocol.ActionResult
	if e != nil || len(b) > 64<<20 || json.Unmarshal(b, &r) != nil {
		return "", "", ErrEvidence
	}
	for _, p := range r.Processes {
		if p.PID == pid && p.Start != "" {
			return p.Start, p.Name, nil
		}
	}
	return "", "", ErrEvidence
}
