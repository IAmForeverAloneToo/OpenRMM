package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
)

// ParseState is a collection's latest parse, listed with the collection.
type ParseState struct {
	Status  string `json:"status"`
	Outcome string `json:"outcome"`
	// Parser is the parser version that produced the results; a newer
	// release may parse the collection again with more.
	Parser     int             `json:"parser"`
	Size       int64           `json:"size"`
	Tables     json.RawMessage `json:"tables"`
	FinishedAt *int64          `json:"finished_at"`
}

// ParseTable summarizes one parsed table in the listing.
type ParseTable struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	Rows  int64  `json:"rows"`
}

// ErrParseBusy: the collection is already being parsed.
var ErrParseBusy = errors.New("the collection is already being parsed")

// parseAttempts parses that ended with the server are restarted; one that
// ends the server this often is given up as crashed.
const parseAttempts = 3

// maxParseOutput bounds one collection's parsed results.
const maxParseOutput = 4 << 30

// queueParseTx queues a collection for parsing unless a parse is already
// waiting or running.
func queueParseTx(ctx context.Context, tx *sql.Tx, job, actor string, at time.Time) (bool, error) {
	r, e := tx.ExecContext(ctx, `INSERT INTO artefact_parses(job_id,status,requested_by,queued_at) VALUES(?,'queued',?,?)
 ON CONFLICT(job_id) DO UPDATE SET status='queued',outcome='',attempts=0,requested_by=excluded.requested_by,queued_at=excluded.queued_at,started_at=NULL,finished_at=NULL
 WHERE artefact_parses.status IN ('succeeded','failed')`, job, actor, at.Unix())
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}

// QueueParse parses a collection (again): older collections, or after a
// release improved the parsers.
func (s *Store) QueueParse(ctx context.Context, caseID, job, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var device, source, action string
	if e = tx.QueryRowContext(ctx, `SELECT device_id,source,action FROM evidence_jobs WHERE id=? AND case_id=? AND status='succeeded'`, job, caseID).Scan(&device, &source, &action); e != nil || action != "" || !artefacts.Parseable(source) {
		return ErrEvidence
	}
	queued, e := queueParseTx(ctx, tx, job, actor, now)
	if e != nil {
		return e
	}
	if !queued {
		return ErrParseBusy
	}
	if _, e = AppendCustody(ctx, tx, caseID, actor, device, "artefacts_parse_requested", map[string]string{"job": job}, nil, "success", now); e != nil {
		return e
	}
	return tx.Commit()
}

// ParseTask is a claimed parse: the collection, where its results go and
// how large they may be.
type ParseTask struct {
	Request artefacts.Request
	JobID   string
	CaseID  string
	Device  string
	// QuotaBound: the size limit is what is left of the evidence quota.
	QuotaBound bool
}

// ClaimParse starts the oldest waiting parse.
func (s *Store) ClaimParse(ctx context.Context, now time.Time) (ParseTask, bool, error) {
	if s.evidence == "" {
		return ParseTask{}, false, nil
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return ParseTask{}, false, e
	}
	defer tx.Rollback()
	var t ParseTask
	var hash string
	e = tx.QueryRowContext(ctx, `SELECT p.job_id,j.case_id,j.device_id,j.source,j.path,j.server_sha256 FROM artefact_parses p JOIN evidence_jobs j ON j.id=p.job_id WHERE p.status='queued' AND j.status='succeeded' ORDER BY p.queued_at,p.job_id LIMIT 1`).Scan(&t.JobID, &t.CaseID, &t.Device, &t.Request.Source, &t.Request.Name, &hash)
	if errors.Is(e, sql.ErrNoRows) {
		return ParseTask{}, false, nil
	}
	if e != nil {
		return ParseTask{}, false, e
	}
	t.Request.MaxOutput = maxParseOutput
	if s.evidenceQuota > 0 {
		used, e := s.quotaUsed(ctx, tx)
		if e != nil {
			return ParseTask{}, false, e
		}
		if left := s.evidenceQuota - used; left < t.Request.MaxOutput {
			t.Request.MaxOutput, t.QuotaBound = max(left, 0), true
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE artefact_parses SET status='running',attempts=attempts+1,started_at=? WHERE job_id=?`, now.Unix(), t.JobID); e != nil {
		return ParseTask{}, false, e
	}
	t.Request.Input = s.stored(hash)
	if t.CaseID == LiveCase {
		t.Request.Input = s.scratch(t.JobID)
	}
	t.Request.Output = filepath.Join(s.evidence, "incoming", t.JobID+".parsed.part")
	t.Request.Temp = filepath.Join(s.evidence, "incoming", t.JobID+".parse")
	s.cleanParse(t)
	if e = os.MkdirAll(t.Request.Temp, 0700); e != nil {
		return ParseTask{}, false, e
	}
	return t, true, tx.Commit()
}

func (s *Store) cleanParse(t ParseTask) {
	_ = os.Remove(t.Request.Output)
	_ = os.RemoveAll(t.Request.Temp)
}

// parsedName is the parsed results' download name.
func parsedName(job string) string { return "parsed-" + job[:min(8, len(job))] + ".zip" }

// FinishParse stores a parse's results like evidence and records them in
// the custody log.
func (s *Store) FinishParse(ctx context.Context, t ParseTask, m artefacts.Manifest, now time.Time) error {
	defer s.cleanParse(t)
	hash, size, e := hashFile(ctx, t.Request.Output)
	if e != nil {
		return s.FailParse(ctx, t, artefacts.OutcomeFailed, now)
	}
	target := s.stored(hash)
	if t.CaseID == LiveCase {
		target = s.scratch(t.JobID) + ".parsed"
	}
	if stored, n, err := hashFile(ctx, target); err != nil || stored != hash || n != size {
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		_ = os.Chmod(target, 0600)
		if e = os.Rename(t.Request.Output, target); e != nil {
			return e
		}
	}
	_ = os.Chmod(target, 0400)
	tables := []ParseTable{}
	var counts []string
	for _, tb := range m.Tables {
		tables = append(tables, ParseTable{Name: tb.Name, Title: tb.Title, Rows: tb.Rows})
		counts = append(counts, tb.Title+": "+strconv.FormatInt(tb.Rows, 10))
	}
	summary, _ := json.Marshal(tables)
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE artefact_parses SET status='succeeded',outcome='ok',parser=?,sha256=?,size=?,tables_json=?,finished_at=? WHERE job_id=? AND status='running' AND job_id IN (SELECT id FROM evidence_jobs WHERE status='succeeded')`, m.Parser, hash, size, string(summary), now.Unix(), t.JobID)
	if e != nil {
		return e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		// The collection was purged meanwhile (results without a case).
		if t.CaseID == LiveCase {
			_ = os.Chmod(target, 0600)
			_ = os.Remove(target)
		}
		return nil
	}
	if t.CaseID != LiveCase {
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO evidence_files(sha256,size,stored_at) VALUES(?,?,?)`, hash, size, now.Unix()); e != nil {
			return e
		}
	}
	errs := len(m.Errors) + m.ErrorsMore
	details := map[string]string{"job": t.JobID, "parser": strconv.Itoa(m.Parser), "tables": strings.Join(counts, ", "), "unparsed_files": strconv.Itoa(errs)}
	if _, e = appendCustodyAnyStatus(ctx, tx, t.CaseID, "system", t.Device, "artefacts_parsed", details, []custody.Evidence{{SHA256: hash, Size: size, Name: parsedName(t.JobID)}}, "success", now); e != nil {
		return e
	}
	return tx.Commit()
}

// FailParse records why a parse ended without results.
func (s *Store) FailParse(ctx context.Context, t ParseTask, outcome string, now time.Time) error {
	defer s.cleanParse(t)
	if outcome == artefacts.OutcomeOutputLimit && t.QuotaBound {
		outcome = "quota"
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.ExecContext(ctx, `UPDATE artefact_parses SET status='failed',outcome=?,finished_at=? WHERE job_id=? AND status='running'`, outcome, now.Unix(), t.JobID)
	if e != nil {
		return e
	}
	if n, _ := r.RowsAffected(); n != 1 {
		return nil
	}
	if _, e = appendCustodyAnyStatus(ctx, tx, t.CaseID, "system", t.Device, "artefacts_parsed", map[string]string{"job": t.JobID, "reason": outcome}, nil, "failure", now); e != nil {
		return e
	}
	return tx.Commit()
}

// RecoverParses restarts parses that were running when the server ended,
// and gives up on those that ended it too often.
func (s *Store) RecoverParses(ctx context.Context, now time.Time) error {
	rows, e := s.rdb.QueryContext(ctx, `SELECT p.job_id,j.case_id,j.device_id FROM artefact_parses p JOIN evidence_jobs j ON j.id=p.job_id WHERE p.status='running' AND p.attempts>=?`, parseAttempts)
	if e != nil {
		return e
	}
	var given []ParseTask
	for rows.Next() {
		var t ParseTask
		if rows.Scan(&t.JobID, &t.CaseID, &t.Device) == nil {
			given = append(given, t)
		}
	}
	rows.Close()
	for _, t := range given {
		if e := s.FailParse(ctx, t, artefacts.OutcomeCrashed, now); e != nil {
			return e
		}
	}
	_, e = s.db.ExecContext(ctx, `UPDATE artefact_parses SET status='queued',started_at=NULL WHERE status='running'`)
	return e
}

// OpenParsed opens a collection's parsed results; with record set the
// opening is recorded in the custody log like a download.
func (s *Store) OpenParsed(ctx context.Context, caseID, job, actor string, record bool, now time.Time) (*os.File, EvidenceJob, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, EvidenceJob{}, e
	}
	defer tx.Rollback()
	var j EvidenceJob
	var hash string
	var size int64
	if e = tx.QueryRowContext(ctx, `SELECT j.id,j.device_id,j.path,j.source,p.sha256,p.size FROM evidence_jobs j JOIN artefact_parses p ON p.job_id=j.id WHERE j.id=? AND j.case_id=? AND j.status='succeeded' AND p.status='succeeded'`, job, caseID).Scan(&j.ID, &j.DeviceID, &j.Path, &j.Source, &hash, &size); e != nil || len(hash) != 64 {
		return nil, j, ErrEvidence
	}
	j.Size = size
	path := s.stored(hash)
	if caseID == LiveCase {
		path = s.scratch(job) + ".parsed"
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, j, errors.New("the parsed results are missing from the evidence store")
	}
	if i, e := f.Stat(); e != nil || i.Size() != size {
		f.Close()
		return nil, j, errors.New("the stored parsed results do not have their recorded size")
	}
	if !record {
		return f, j, nil
	}
	if _, e = appendCustodyAnyStatus(ctx, tx, caseID, actor, j.DeviceID, "evidence_downloaded", map[string]string{"job": job, "parsed": "true"}, []custody.Evidence{{SHA256: hash, Size: size, Name: parsedName(job)}}, "success", now); e != nil {
		f.Close()
		return nil, j, e
	}
	if e = tx.Commit(); e != nil {
		f.Close()
		return nil, j, e
	}
	return f, j, nil
}
