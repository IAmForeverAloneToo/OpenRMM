package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Fleet searches and indicator hunts. A hunt sends
// one response action to each target device as an evidence job tagged with
// the hunt: results are verified and stored like other action results, as
// case evidence or, without a case (LiveCase), for 24 hours. Offline devices
// are waited for up to a week.

const (
	huntWait = 7 * 24 * time.Hour
	// MaxHuntTargets bounds the devices one search reaches.
	MaxHuntTargets = 500
	// huntQueue bounds the searches waiting for one device: a device that
	// returns after days works through them before newer work.
	huntQueue = 10
	// huntResultMax: larger results are not read to count their events.
	huntResultMax = 8 << 20
)

var (
	ErrHunt = errors.New("search unavailable; check the targets, filter and evidence store")
	// ErrHuntSize: the devices and group members exceed MaxHuntTargets.
	ErrHuntSize = errors.New("too many devices for one search")
)

// Hunt is a fleet search with its targets.
type Hunt struct {
	ID     string               `json:"id"`
	Kind   string               `json:"kind"`
	CaseID string               `json:"case_id"`
	Actor  string               `json:"actor"`
	Filter protocol.EventFilter `json:"filter"`
	// Spec is an indicator hunt's indicators (kind "indicators").
	Spec        *protocol.HuntSpec `json:"spec,omitempty"`
	CreatedAt   int64              `json:"created_at"`
	ExpiresAt   int64              `json:"expires_at"`
	CancelledAt *int64             `json:"cancelled_at"`
	// Problems names target devices that were not searched, with the reason.
	Problems []HuntProblem `json:"problems"`
	Targets  []HuntTarget  `json:"targets"`
}

type HuntProblem struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

// HuntTarget is one device's job; Events (matching events, or matches of an
// indicator hunt), More and Skipped come from its result once it is stored
// (Result is false until then).
type HuntTarget struct {
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	JobID      string `json:"job_id"`
	Status     string `json:"status"`
	Outcome    string `json:"outcome"`
	FinishedAt *int64 `json:"finished_at"`
	Result     bool   `json:"result"`
	Searched   string `json:"searched,omitempty"`
	Events     int    `json:"events"`
	More       bool   `json:"more"`
	Skipped    int    `json:"skipped"`
}

// HuntSummary is a hunt in the list.
type HuntSummary struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	CaseID      string `json:"case_id"`
	Actor       string `json:"actor"`
	Channel     string `json:"channel"`
	Indicators  int    `json:"indicators"`
	Files       bool   `json:"files"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at"`
	CancelledAt *int64 `json:"cancelled_at"`
	Targets     int    `json:"targets"`
	Waiting     int    `json:"waiting"`
	Finished    int    `json:"finished"`
	Problems    int    `json:"problems"`
}

// StartLogSearch starts an event log search on the devices and
// group members chosen, into caseID or LiveCase. Devices that cannot run it
// are listed as problems; the search fails (ErrHunt) when none can.
func (s *Store) StartLogSearch(ctx context.Context, caseID string, devices, groups []string, f protocol.EventFilter, actor string, now time.Time) (Hunt, error) {
	f.Before, f.Limit = 0, protocol.MaxEventPage
	h := Hunt{Kind: "log_search", Filter: f}
	spec, _ := json.Marshal(f)
	return s.startHunt(ctx, h, string(spec), protocol.ResponseAction{Kind: "events", Events: &f}, caseID, devices, groups, actor, now, func(tx *sql.Tx, device string) string {
		var version int
		_ = tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT capability_version FROM device_event_logs WHERE device_id=?),0)`, device).Scan(&version)
		if version < 3 {
			return "The device's agent cannot search event logs; update it."
		}
		return ""
	})
}

// StartIndicatorHunt starts an indicator hunt like a log search.
func (s *Store) StartIndicatorHunt(ctx context.Context, caseID string, devices, groups []string, spec protocol.HuntSpec, actor string, now time.Time) (Hunt, error) {
	h := Hunt{Kind: "indicators", Spec: &spec}
	text, _ := json.Marshal(spec)
	// Abilities are read before the write transaction (single connection).
	able := map[string]bool{}
	if targets, e := s.huntTargets(ctx, devices, groups); e == nil {
		for _, t := range targets {
			able[t.ID] = s.HasAbility(ctx, t.ID, protocol.AbilityHunt)
		}
	}
	return s.startHunt(ctx, h, string(text), protocol.ResponseAction{Kind: "hunt", Hunt: &spec}, caseID, devices, groups, actor, now, func(_ *sql.Tx, device string) string {
		if !able[device] {
			return "The device's agent cannot run indicator hunts; update it."
		}
		return ""
	})
}

// startHunt queues the action on each target in scope that can run it
// (ready returns a reason when one cannot).
func (s *Store) startHunt(ctx context.Context, h Hunt, spec string, action protocol.ResponseAction, caseID string, devices, groups []string, actor string, now time.Time, ready func(*sql.Tx, string) string) (Hunt, error) {
	h.CaseID, h.Actor, h.CreatedAt, h.ExpiresAt, h.Problems, h.Targets = caseID, actor, now.Unix(), now.Add(huntWait).Unix(), []HuntProblem{}, []HuntTarget{}
	if s.evidence == "" || !action.Valid() || len(devices) > MaxHuntTargets || len(groups) > 100 || len(devices)+len(groups) == 0 || caseID != LiveCase && !protocol.ValidID(caseID) {
		return h, ErrHunt
	}
	for _, id := range devices {
		if !protocol.ValidID(id) {
			return h, ErrHunt
		}
	}
	for _, id := range groups {
		if !ValidOrganizationID(id) {
			return h, ErrHunt
		}
	}
	id, e := evidenceID()
	if e != nil {
		return h, e
	}
	h.ID = id
	// Resolve the targets; switch states are read outside the write
	// transaction (the store has a single connection).
	targets, e := s.huntTargets(ctx, devices, groups)
	if e != nil {
		return h, e
	}
	if len(targets) == 0 {
		return h, ErrHunt
	}
	if len(targets) > MaxHuntTargets {
		return h, ErrHuntSize
	}
	off := map[string]bool{}
	for _, t := range targets {
		disabled, e1 := s.DisabledFeatures(ctx, t.ID)
		locks, e2 := s.FeatureLocks(ctx, t.ID)
		if e1 != nil || e2 != nil {
			return h, errors.Join(e1, e2)
		}
		off[t.ID] = slices.Contains(disabled, "response") || slices.Contains(locks, "response")
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return h, e
	}
	defer tx.Rollback()
	// Outside the account's scope: a chosen device refuses the search as
	// unknown; group members are left out silently, so nothing about them is
	// shown. A group without a member in scope is unknown too.
	inScope, groupHit := []OrganizedDevice{}, map[string]bool{}
	for _, t := range targets {
		if authorizeActor(ctx, tx, actor, t.ID, "response") != nil {
			if slices.Contains(devices, t.ID) {
				return h, ErrHunt
			}
			continue
		}
		inScope = append(inScope, t)
		groupHit[t.GroupID] = true
	}
	for _, g := range groups {
		if !groupHit[g] {
			return h, ErrHunt
		}
	}
	text := action.Text()
	for _, t := range inScope {
		var waiting int
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_jobs WHERE device_id=? AND hunt_id<>'' AND status='queued'`, t.ID).Scan(&waiting)
		reason := ""
		if off[t.ID] {
			reason = "Incident response is switched off on the device."
		} else if reason = ready(tx, t.ID); reason == "" && waiting >= huntQueue {
			reason = "Too many searches are already waiting for this device."
		}
		if reason != "" {
			h.Problems = append(h.Problems, HuntProblem{DeviceID: t.ID, Hostname: t.Hostname, Reason: reason})
			continue
		}
		job, e := evidenceID()
		if e != nil {
			return h, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO evidence_jobs(id,case_id,device_id,actor,path,status,chunk_size,created_at,expires_at,source,action,hunt_id) VALUES(?,?,?,?,?,'queued',?,?,?,'file',?,?)`, job, caseID, t.ID, actor, action.Label(), EvidenceChunk, now.Unix(), now.Add(huntWait).Unix(), text, id); e != nil {
			return h, errors.New("cannot queue the search")
		}
		if _, e = AppendCustody(ctx, tx, caseID, actor, t.ID, "action_requested", map[string]string{"job": job, "action": action.Label(), "spec": text, "hunt": id}, nil, "success", now); e != nil {
			return h, e
		}
		h.Targets = append(h.Targets, HuntTarget{DeviceID: t.ID, Hostname: t.Hostname, JobID: job, Status: "queued"})
	}
	if len(h.Targets) == 0 {
		return h, ErrHunt
	}
	problems, _ := json.Marshal(h.Problems)
	if _, e = tx.ExecContext(ctx, `INSERT INTO hunts(id,kind,case_id,actor,spec,problems_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`, id, h.Kind, caseID, actor, spec, string(problems), h.CreatedAt, h.ExpiresAt); e != nil {
		return h, errors.New("cannot record the search")
	}
	return h, tx.Commit()
}

// huntTargets resolves chosen devices and group members (active devices).
func (s *Store) huntTargets(ctx context.Context, devices, groups []string) ([]OrganizedDevice, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	o, e := organizationTx(ctx, tx, true)
	if e != nil {
		return nil, e
	}
	known := map[string]bool{}
	for _, g := range o.Groups {
		known[g.ID] = true
	}
	for _, g := range groups {
		if !known[g] {
			return nil, ErrHunt
		}
	}
	out, found := []OrganizedDevice{}, map[string]bool{}
	for _, d := range o.Devices {
		if slices.Contains(devices, d.ID) || d.GroupID != "" && slices.Contains(groups, d.GroupID) {
			out = append(out, d)
			found[d.ID] = true
		}
	}
	for _, d := range devices {
		if !found[d] {
			return nil, ErrHunt
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, tx.Commit()
}

// HuntDetail reads a hunt with its targets; results stored since the last
// read are summarised (counts only) and cached.
func (s *Store) HuntDetail(ctx context.Context, id string) (Hunt, error) {
	h := Hunt{Problems: []HuntProblem{}, Targets: []HuntTarget{}}
	var filter, problems string
	e := s.db.QueryRowContext(ctx, `SELECT id,kind,case_id,actor,spec,problems_json,created_at,expires_at,cancelled_at FROM hunts WHERE id=?`, id).Scan(&h.ID, &h.Kind, &h.CaseID, &h.Actor, &filter, &problems, &h.CreatedAt, &h.ExpiresAt, &h.CancelledAt)
	if errors.Is(e, sql.ErrNoRows) {
		return h, ErrHunt
	}
	if e != nil {
		return h, e
	}
	if json.Unmarshal([]byte(problems), &h.Problems) != nil {
		return h, ErrHunt
	}
	if h.Kind == "indicators" {
		h.Spec = new(protocol.HuntSpec)
		if json.Unmarshal([]byte(filter), h.Spec) != nil {
			return h, ErrHunt
		}
	} else if json.Unmarshal([]byte(filter), &h.Filter) != nil {
		return h, ErrHunt
	}
	rows, e := s.db.QueryContext(ctx, `SELECT j.id,j.device_id,COALESCE(d.hostname,''),j.status,j.outcome,j.finished_at,j.server_sha256,j.size,r.outcome,COALESCE(r.events,0),COALESCE(r.more,0),COALESCE(r.skipped,0) FROM evidence_jobs j LEFT JOIN devices d ON d.id=j.device_id LEFT JOIN hunt_results r ON r.job_id=j.id WHERE j.hunt_id=? ORDER BY d.hostname,j.id`, id)
	if e != nil {
		return h, e
	}
	type pending struct {
		index     int
		job, hash string
		size      int64
	}
	var missing []pending
	for rows.Next() {
		var t HuntTarget
		var hash string
		var size int64
		var searched *string
		if e = rows.Scan(&t.JobID, &t.DeviceID, &t.Hostname, &t.Status, &t.Outcome, &t.FinishedAt, &hash, &size, &searched, &t.Events, &t.More, &t.Skipped); e != nil {
			rows.Close()
			return h, e
		}
		if searched != nil {
			t.Result, t.Searched = true, *searched
		} else if t.Status == "succeeded" {
			missing = append(missing, pending{len(h.Targets), t.JobID, hash, size})
		}
		h.Targets = append(h.Targets, t)
	}
	rows.Close()
	// Each result is read once (not an evidence access: only counts are
	// kept); one that is too large or cannot be read is cached as unreadable.
	for _, m := range missing {
		t := &h.Targets[m.index]
		t.Result, t.Searched = true, "unreadable"
		path := s.stored(m.hash)
		if h.CaseID == LiveCase {
			path = s.scratch(m.job)
		}
		var r protocol.ActionResult
		if m.size > 0 && m.size <= huntResultMax && len(m.hash) == 64 {
			if b, e := os.ReadFile(path); e == nil && len(b) <= huntResultMax && json.Unmarshal(b, &r) == nil {
				switch {
				case r.EventLog != nil:
					t.Searched, t.Events, t.More, t.Skipped = r.EventLog.Outcome, len(r.EventLog.Events), r.EventLog.More, r.EventLog.Skipped
				case r.Hunt != nil:
					t.Searched, t.Events, t.More, t.Skipped = r.Hunt.Outcome, len(r.Hunt.Matches), r.Hunt.More, r.Hunt.Skipped
				}
			}
		}
		_, _ = s.db.ExecContext(ctx, `INSERT OR IGNORE INTO hunt_results(job_id,outcome,events,more,skipped) VALUES(?,?,?,?,?)`, m.job, t.Searched, t.Events, t.More, t.Skipped)
	}
	return h, nil
}

// Hunts lists searches, newest first: all of them, or one account's.
func (s *Store) Hunts(ctx context.Context, actor string, all bool) ([]HuntSummary, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT h.id,h.kind,h.case_id,h.actor,h.spec,h.problems_json,h.created_at,h.expires_at,h.cancelled_at,
 (SELECT COUNT(*) FROM evidence_jobs j WHERE j.hunt_id=h.id),
 (SELECT COUNT(*) FROM evidence_jobs j WHERE j.hunt_id=h.id AND j.status IN ('queued','dispatched','uploading','verifying'))
 FROM hunts h WHERE ? OR h.actor=? ORDER BY h.created_at DESC,h.id LIMIT 200`, all, actor)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []HuntSummary{}
	for rows.Next() {
		var v HuntSummary
		var spec, problems string
		if e = rows.Scan(&v.ID, &v.Kind, &v.CaseID, &v.Actor, &spec, &problems, &v.CreatedAt, &v.ExpiresAt, &v.CancelledAt, &v.Targets, &v.Waiting); e != nil {
			return nil, e
		}
		var f protocol.EventFilter
		var hs protocol.HuntSpec
		var p []HuntProblem
		if v.Kind == "indicators" {
			_ = json.Unmarshal([]byte(spec), &hs)
		} else {
			_ = json.Unmarshal([]byte(spec), &f)
		}
		_ = json.Unmarshal([]byte(problems), &p)
		v.Channel, v.Indicators, v.Files, v.Finished, v.Problems = f.Channel, len(hs.Indicators), hs.Files, v.Targets-v.Waiting, len(p)
		out = append(out, v)
	}
	return out, rows.Err()
}

// CancelHunt stops a search: jobs not yet handed to their device are
// cancelled; ones already running finish.
func (s *Store) CancelHunt(ctx context.Context, id, actor string, now time.Time) error {
	h, e := s.HuntDetail(ctx, id)
	if e != nil {
		return e
	}
	if _, e = s.db.ExecContext(ctx, `UPDATE hunts SET cancelled_at=? WHERE id=? AND cancelled_at IS NULL`, now.Unix(), id); e != nil {
		return e
	}
	for _, t := range h.Targets {
		if t.Status == "queued" {
			if e := s.cancelJob(ctx, h.CaseID, t.JobID, actor, now); e != nil && !errors.Is(e, ErrEvidence) {
				return e
			}
		}
	}
	return nil
}

// HuntJobCase names the case of a hunt's job, for reading its result.
func (s *Store) HuntJobCase(ctx context.Context, hunt, job string) (caseID, device string, err error) {
	if e := s.db.QueryRowContext(ctx, `SELECT case_id,device_id FROM evidence_jobs WHERE id=? AND hunt_id=?`, job, hunt).Scan(&caseID, &device); e != nil {
		return "", "", ErrHunt
	}
	return caseID, device, nil
}

// cancelWaitingHuntJobs cancels a case's search jobs still waiting for their
// device when the case is closed: an offline target must not keep
// the case open for a week.
func cancelWaitingHuntJobs(ctx context.Context, tx *sql.Tx, caseID, actor string, now time.Time) error {
	rows, e := tx.QueryContext(ctx, `SELECT id,device_id,path FROM evidence_jobs WHERE case_id=? AND hunt_id<>'' AND status='queued'`, caseID)
	if e != nil {
		return e
	}
	type job struct{ id, device, path string }
	var jobs []job
	for rows.Next() {
		var j job
		if e = rows.Scan(&j.id, &j.device, &j.path); e != nil {
			rows.Close()
			return e
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	for _, j := range jobs {
		if _, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='cancelled',outcome='cancelled',finished_at=? WHERE id=? AND status='queued'`, now.Unix(), j.id); e != nil {
			return e
		}
		if _, e = AppendCustody(ctx, tx, caseID, actor, j.device, "action_cancelled", map[string]string{"job": j.id, "path": j.path, "reason": "case_closed"}, nil, "cancelled", now); e != nil {
			return e
		}
	}
	return nil
}
