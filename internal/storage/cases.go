package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
)

// ErrCase covers unknown cases, closed cases and invalid input.
var ErrCase = errors.New("case unavailable, closed or invalid; reload and try again")

type Case struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	CreatedBy string `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	Entries   int64  `json:"entries"`
}

// CustodyEntry is a stored entry, decoded for display, with its hash.
type CustodyEntry struct {
	custody.Entry
	Hash string `json:"hash"`
	Text string `json:"-"`
}

// CaseDetail is a case with its whole custody chain and the chain check.
type CaseDetail struct {
	Case
	Entries  []CustodyEntry `json:"entries"`
	Head     string         `json:"head"`
	Verified bool           `json:"verified"`
	Problem  string         `json:"problem,omitempty"`
	// Actors maps technician actors ("technician:<id>") to their current
	// usernames for display; entries keep the stable ID.
	Actors map[string]string `json:"actors"`
}

func validText(s string, limit int, multiline bool) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t')) {
			return false
		}
	}
	return true
}

// LiveCase is the built-in record for live response sessions without a case
// (migration 039). It is never listed or shown as a case; its jobs
// write the audit log instead of a custody log.
const LiveCase = "00000000000000000000000000000000"

// AppendCustody adds an entry to an open case inside tx. Later steps call it
// in the same transaction as the action they record. For LiveCase it writes
// an audit event instead.
func AppendCustody(ctx context.Context, tx *sql.Tx, caseID, actor, deviceID, action string, details map[string]string, evidence []custody.Evidence, outcome string, now time.Time) (custody.Entry, error) {
	if caseID == LiveCase {
		return custody.Entry{}, liveAudit(ctx, tx, actor, deviceID, action, details, outcome, now)
	}
	var status string
	if e := tx.QueryRowContext(ctx, `SELECT status FROM cases WHERE id=?`, caseID).Scan(&status); e != nil || status != "open" {
		return custody.Entry{}, ErrCase
	}
	return appendCustodyAnyStatus(ctx, tx, caseID, actor, deviceID, action, details, evidence, outcome, now)
}

// appendCustodyAnyStatus also records in closed cases: access to their
// evidence must still be logged.
func appendCustodyAnyStatus(ctx context.Context, tx *sql.Tx, caseID, actor, deviceID, action string, details map[string]string, evidence []custody.Evidence, outcome string, now time.Time) (custody.Entry, error) {
	if caseID == LiveCase {
		return custody.Entry{}, liveAudit(ctx, tx, actor, deviceID, action, details, outcome, now)
	}
	var exists int
	if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM cases WHERE id=?`, caseID).Scan(&exists); e != nil || exists != 1 {
		return custody.Entry{}, ErrCase
	}
	prev, sequence := custody.Genesis, int64(0)
	e := tx.QueryRowContext(ctx, `SELECT sequence,hash FROM custody_entries WHERE case_id=? ORDER BY sequence DESC LIMIT 1`, caseID).Scan(&sequence, &prev)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return custody.Entry{}, errors.New("cannot read custody log")
	}
	entry := custody.Entry{Version: custody.Version, CaseID: caseID, Sequence: sequence + 1, At: custody.Stamp(now), Actor: actor, DeviceID: deviceID, Action: action, Details: details, Evidence: evidence, Outcome: outcome, PrevHash: prev}
	text, e := custody.Encode(entry)
	if e != nil {
		return custody.Entry{}, errors.New("cannot encode custody entry")
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO custody_entries(case_id,sequence,entry_json,hash,at,device_id,action) VALUES(?,?,?,?,?,?,?)`, caseID, entry.Sequence, text, custody.Hash(prev, text), now.UnixMilli(), deviceID, action); e != nil {
		return custody.Entry{}, errors.New("cannot append custody entry")
	}
	if _, e = tx.ExecContext(ctx, `UPDATE cases SET updated_at=? WHERE id=?`, now.Unix(), caseID); e != nil {
		return custody.Entry{}, errors.New("cannot update case")
	}
	return entry, nil
}

// liveAudit records a case-less live response step in the audit log (no
// details beyond the job and action; results are not kept as evidence).
func liveAudit(ctx context.Context, tx *sql.Tx, actor, deviceID, action string, details map[string]string, outcome string, now time.Time) error {
	target := deviceID
	if job := details["job"]; job != "" {
		target += "/" + job
	}
	if outcome == "" || len(outcome) > 64 {
		outcome = "success"
	}
	return auditDevice(ctx, tx, now, actor, "live_"+action, target, outcome)
}

func (s *Store) CreateCase(ctx context.Context, title, actor string, now time.Time) (Case, error) {
	if !validText(title, 200, false) {
		return Case{}, ErrCase
	}
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return Case{}, errors.New("cannot create case identifier")
	}
	c := Case{ID: hex.EncodeToString(b), Title: title, Status: "open", CreatedBy: actor, CreatedAt: now.Unix(), UpdatedAt: now.Unix(), Entries: 1}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return Case{}, errors.New("cannot begin case creation")
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `INSERT INTO cases(id,title,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?)`, c.ID, title, "open", actor, now.Unix(), now.Unix()); e != nil {
		return Case{}, errors.New("cannot store case")
	}
	if _, e = AppendCustody(ctx, tx, c.ID, actor, "", "case_opened", map[string]string{"title": title}, nil, "success", now); e != nil {
		return Case{}, e
	}
	return c, tx.Commit()
}

// AddCaseNote records a note in an open case's custody log.
func (s *Store) AddCaseNote(ctx context.Context, id, actor, text string, now time.Time) error {
	if !validText(text, 8000, true) || id == LiveCase {
		return ErrCase
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin note")
	}
	defer tx.Rollback()
	if _, e = AppendCustody(ctx, tx, id, actor, "", "note", map[string]string{"text": text}, nil, "success", now); e != nil {
		return e
	}
	return tx.Commit()
}

// SetCaseStatus closes or reopens a case; both are custody entries. A closed
// case accepts no entries until it is reopened.
func (s *Store) SetCaseStatus(ctx context.Context, id, status, actor, reason string, now time.Time) error {
	if status != "open" && status != "closed" || reason != "" && !validText(reason, 2000, true) || id == LiveCase {
		return ErrCase
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return errors.New("cannot begin case update")
	}
	defer tx.Rollback()
	var current string
	if e = tx.QueryRowContext(ctx, `SELECT status FROM cases WHERE id=?`, id).Scan(&current); e != nil || current == status {
		return ErrCase
	}
	details := map[string]string{}
	if reason != "" {
		details["reason"] = reason
	}
	if status == "open" {
		if _, e = tx.ExecContext(ctx, `UPDATE cases SET status='open' WHERE id=?`, id); e != nil {
			return errors.New("cannot reopen case")
		}
		_, e = AppendCustody(ctx, tx, id, actor, "", "case_reopened", details, nil, "success", now)
	} else {
		// Searches still waiting for an offline device are cancelled;
		// collections still running would have nowhere to record their end.
		if e := cancelWaitingHuntJobs(ctx, tx, id, actor, now); e != nil {
			return e
		}
		if n, e := activeEvidence(ctx, tx, id); e != nil || n > 0 {
			return ErrCase
		}
		if _, e = AppendCustody(ctx, tx, id, actor, "", "case_closed", details, nil, "success", now); e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `UPDATE cases SET status='closed' WHERE id=?`, id)
	}
	if e != nil {
		return e
	}
	return tx.Commit()
}

func scanCase(row interface{ Scan(...any) error }) (Case, error) {
	var c Case
	e := row.Scan(&c.ID, &c.Title, &c.Status, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.Entries)
	return c, e
}

const caseColumns = `c.id,c.title,c.status,c.created_by,c.created_at,c.updated_at,(SELECT COUNT(*) FROM custody_entries x WHERE x.case_id=c.id)`

// Cases lists cases, open ones first, then most recently updated.
func (s *Store) Cases(ctx context.Context) ([]Case, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT `+caseColumns+` FROM cases c WHERE c.id<>? ORDER BY c.status='closed', c.updated_at DESC, c.id LIMIT 1000`, LiveCase)
	if e != nil {
		return nil, errors.New("cannot list cases")
	}
	defer rows.Close()
	out := []Case{}
	for rows.Next() {
		c, e := scanCase(rows)
		if e != nil {
			return nil, errors.New("cannot read case")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CaseRecords returns a case's stored custody records in order.
func (s *Store) CaseRecords(ctx context.Context, id string) (Case, []custody.Record, error) {
	if id == LiveCase {
		return Case{}, nil, ErrCase
	}
	c, e := scanCase(s.db.QueryRowContext(ctx, `SELECT `+caseColumns+` FROM cases c WHERE c.id=?`, id))
	if errors.Is(e, sql.ErrNoRows) {
		return Case{}, nil, ErrCase
	}
	if e != nil {
		return Case{}, nil, errors.New("cannot read case")
	}
	rows, e := s.db.QueryContext(ctx, `SELECT entry_json,hash FROM custody_entries WHERE case_id=? ORDER BY sequence`, id)
	if e != nil {
		return Case{}, nil, errors.New("cannot read custody log")
	}
	defer rows.Close()
	records := []custody.Record{}
	for rows.Next() {
		var r custody.Record
		if rows.Scan(&r.Entry, &r.Hash) != nil {
			return Case{}, nil, errors.New("cannot read custody log")
		}
		records = append(records, r)
	}
	return c, records, rows.Err()
}

// CaseDetail returns a case with its decoded entries and verifies the chain;
// a broken chain is reported, not hidden.
func (s *Store) CaseDetail(ctx context.Context, id string) (CaseDetail, error) {
	c, records, e := s.CaseRecords(ctx, id)
	if e != nil {
		return CaseDetail{}, e
	}
	d := CaseDetail{Case: c, Entries: []CustodyEntry{}, Actors: map[string]string{}}
	d.Head, e = custody.Verify(id, records)
	d.Verified = e == nil
	if e != nil {
		d.Problem = e.Error()
	}
	for _, r := range records {
		x := CustodyEntry{Hash: r.Hash, Text: r.Entry}
		_ = json.Unmarshal([]byte(r.Entry), &x.Entry)
		d.Entries = append(d.Entries, x)
		if id, ok := strings.CutPrefix(x.Actor, "technician:"); ok {
			if _, done := d.Actors[x.Actor]; !done {
				var name string
				if s.db.QueryRowContext(ctx, `SELECT username FROM technicians WHERE id=?`, id).Scan(&name) == nil {
					d.Actors[x.Actor] = name
				}
			}
		}
	}
	return d, nil
}
