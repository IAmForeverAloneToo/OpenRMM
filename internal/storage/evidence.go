package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// ErrEvidence covers refused collections: unknown or finished jobs, invalid
// paths, a switched-off response feature, limits and quota.
var ErrEvidence = errors.New("evidence collection unavailable; check the case, device, path, limits and quota")

const (
	// EvidenceChunk is the upload chunk size; EvidenceMaxFile the largest
	// collectable file (16 GB).
	EvidenceChunk   = 8 << 20
	EvidenceMaxFile = 16 << 30
	// Jobs wait this long for the device, then this long for the agent to
	// start, and fail when an upload makes no progress for this long. An
	// upload idle for evidenceResume is handed to its device again, so an
	// agent that restarted resumes it.
	evidenceQueueLife   = time.Hour
	evidenceStartWindow = 5 * time.Minute
	evidenceStall       = 30 * time.Minute
	// A response action runs before its result starts uploading (the agent
	// bounds it to 20 minutes).
	actionStartWindow = 30 * time.Minute
	evidenceResume    = 3 * time.Minute
	evidenceAttempts  = 5
	maxActiveEvidence = 20
	maxDeviceEvidence = 2
)

type EvidenceJob struct {
	ID           string `json:"id"`
	CaseID       string `json:"case_id"`
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	Actor        string `json:"actor"`
	Path         string `json:"path"`
	Status       string `json:"status"`
	Outcome      string `json:"outcome"`
	ChunkSize    int64  `json:"chunk_size"`
	Size         int64  `json:"size"`
	Received     int64  `json:"received_chunks"`
	Resolved     string `json:"resolved_path"`
	FileModified int64  `json:"file_modified"`
	FileCreated  int64  `json:"file_created"`
	DeviceSHA256 string `json:"device_sha256"`
	ServerSHA256 string `json:"server_sha256"`
	CreatedAt    int64  `json:"created_at"`
	FinishedAt   *int64 `json:"finished_at"`
	ExpiresAt    int64  `json:"-"`
	// Kind is "file" (collected from a device) or "transcript".
	Kind string `json:"kind"`
	// Source is "file" or "hive"; Meta is what the agent reported
	// (protocol.EvidenceMeta); ParentID names the collection whose alternate
	// data stream this is.
	Source   string          `json:"source"`
	Meta     json.RawMessage `json:"meta,omitempty"`
	ParentID string          `json:"parent_id,omitempty"`
	// Action is the response action spec (Source is then "action" and
	// Path its label).
	Action string `json:"action,omitempty"`
	// Query is the event XPath of an event log export (Source "evtx", Path
	// the channel; empty for the whole channel).
	Query string `json:"query,omitempty"`
}

var codeHash = regexp.MustCompile(`"code_hash":"[0-9a-f]{64}"`)

// MarshalJSON shows a job without an isolation's release code hash:
// only the device needs it.
func (j EvidenceJob) MarshalJSON() ([]byte, error) {
	type plain EvidenceJob
	p := plain(j)
	p.Action = codeHash.ReplaceAllString(p.Action, `"code_hash":""`)
	return json.Marshal(p)
}

// Name is the evidence file's download name.
func (j EvidenceJob) Name() string {
	switch {
	case j.Kind == "transcript":
		return transcriptName(j.ID)
	case j.Action != "":
		a, _ := protocol.ParseAction(j.Action)
		return "action-" + a.Kind + "-" + j.ID + ".json"
	case j.Source == "hive":
		return "hive-" + strings.ReplaceAll(j.Path, ":", "-") + ".dat"
	case j.Source == "evtx":
		return "eventlog-" + strings.NewReplacer("/", "-", " ", "-", "%", "-").Replace(j.Path) + ".evtx"
	case j.Source == "triage":
		return "triage-" + safeName(j.Path) + "-" + j.ID[:min(8, len(j.ID))] + ".zip"
	}
	// An alternate data stream (file.txt:Zone.Identifier) becomes
	// file.txt_Zone.Identifier.
	return strings.ReplaceAll(filepath.Base(strings.ReplaceAll(j.Path[min(2, len(j.Path)):], `\`, "/")), ":", "_")
}

var windowsPath = regexp.MustCompile(`^[A-Za-z]:\\`)

// ValidEvidencePath accepts an absolute local Windows path, optionally with
// an alternate data stream (C:\x\file.txt:Zone.Identifier); the
// agent applies the full path, link and deny-list rules.
func ValidEvidencePath(p string) bool {
	if !windowsPath.MatchString(p) || len(p) > 1024 || strings.TrimSpace(p) != p {
		return false
	}
	file, _, ok := protocol.SplitStream(p[2:])
	if !ok || strings.Contains(file, `\\`) || strings.HasSuffix(file, `\`) {
		return false
	}
	for _, r := range file {
		if unicode.IsControl(r) || strings.ContainsRune(`/<>"|?*`, r) {
			return false
		}
	}
	return true
}

// ValidEvidenceSource checks a requested source and path: a file path, a
// registry hive name (protocol.ValidHive) or an event log channel.
func ValidEvidenceSource(source, path string) bool {
	switch source {
	case "file":
		return ValidEvidencePath(path)
	case "hive":
		return protocol.ValidHive(path)
	case "evtx":
		return eventlogs.ValidChannel(path)
	}
	return false
}

// UseEvidence sets the evidence directory and quota (bytes) at start-up.
func (s *Store) UseEvidence(dir string, quota int64) error {
	if dir == "" {
		return nil // evidence collection stays unavailable
	}
	for _, d := range []string{dir, filepath.Join(dir, "incoming"), filepath.Join(dir, "sha256"), filepath.Join(dir, "scratch")} {
		if e := os.MkdirAll(d, 0700); e != nil {
			return errors.New("cannot create the evidence directory")
		}
	}
	s.evidence, s.evidenceQuota = dir, quota
	return nil
}
func (s *Store) incoming(job string) string {
	return filepath.Join(s.evidence, "incoming", job+".part")
}
func (s *Store) stored(hash string) string {
	return filepath.Join(s.evidence, "sha256", hash[:2], hash)
}

// scratch holds a case-less live response result for 24 hours,
// outside the evidence store.
func (s *Store) scratch(job string) string {
	return filepath.Join(s.evidence, "scratch", job)
}

// ErrEventExport: the device's agent predates event log export.
var ErrEventExport = errors.New("the device's agent cannot export event logs; update it")

// liveResultLife is how long a case-less live response result is kept.
const liveResultLife = 24 * time.Hour

// liveAuditLife is how long the audit events of case-less live response
// steps are kept.
const liveAuditLife = 365 * 24 * time.Hour

func evidenceID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", errors.New("cannot create job identifier")
	}
	return hex.EncodeToString(b), nil
}

// QueueEvidence asks a device for a file, recorded in the case's custody log.
// The caller checks the actor's response permission and device access.
func (s *Store) QueueEvidence(ctx context.Context, caseID, deviceID, path, actor string, now time.Time) (string, error) {
	return s.QueueEvidenceSource(ctx, caseID, deviceID, "file", path, actor, now)
}

// QueueEvidenceSource asks a device for a file or a registry hive.
func (s *Store) QueueEvidenceSource(ctx context.Context, caseID, deviceID, source, path, actor string, now time.Time) (string, error) {
	if !ValidEvidenceSource(source, path) || caseID == LiveCase {
		return "", ErrEvidence
	}
	return s.queueJob(ctx, caseID, deviceID, source, path, "", "", "", actor, now)
}

// QueueEventExport asks a device for an .evtx export of an event log channel:
// the whole channel (query "") or the events matching an
// eventlogs.ExportQuery. Session names the live response session, or is
// empty for a case-page request (LiveCase is then refused).
func (s *Store) QueueEventExport(ctx context.Context, caseID, deviceID, session, channel, query, actor string, now time.Time) (string, error) {
	if !eventlogs.ValidChannel(channel) || !eventlogs.ValidExportQuery(query) || session != "" && !protocol.ValidID(session) || session == "" && caseID == LiveCase {
		return "", ErrEvidence
	}
	// Agents that export report event logs capability version 2 or later.
	var version int
	if e := s.db.QueryRowContext(ctx, `SELECT capability_version FROM device_event_logs WHERE device_id=?`, deviceID).Scan(&version); e != nil || version < 2 {
		return "", ErrEventExport
	}
	return s.queueJob(ctx, caseID, deviceID, "evtx", channel, query, "", session, actor, now)
}

// QueueSessionJob starts a live response command's job: a file or
// hive collection (action "") or a response action, recorded to the
// session's case or, with LiveCase, to the audit log only.
func (s *Store) QueueSessionJob(ctx context.Context, caseID, deviceID, session, source, path string, a *protocol.ResponseAction, actor string, now time.Time) (string, error) {
	if !protocol.ValidID(session) {
		return "", ErrEvidence
	}
	if a != nil {
		if !a.Valid() {
			return "", ErrEvidence
		}
		if e := s.actionAbility(ctx, deviceID, *a); e != nil {
			return "", e
		}
		return s.queueJob(ctx, caseID, deviceID, "file", a.Label(), "", a.Text(), session, actor, now)
	}
	if !ValidEvidenceSource(source, path) {
		return "", ErrEvidence
	}
	return s.queueJob(ctx, caseID, deviceID, source, path, "", "", session, actor, now)
}

// QueueAction asks a device to run a response action; its result
// document becomes case evidence.
func (s *Store) QueueAction(ctx context.Context, caseID, deviceID string, a protocol.ResponseAction, actor string, now time.Time) (string, error) {
	if !a.Valid() || caseID == LiveCase {
		return "", ErrEvidence
	}
	if e := s.actionAbility(ctx, deviceID, a); e != nil {
		return "", e
	}
	return s.queueJob(ctx, caseID, deviceID, "file", a.Label(), "", a.Text(), "", actor, now)
}

// ErrActionUnsupported: the device's agent predates the action (it would
// discard it).
var ErrActionUnsupported = errors.New("the device's agent cannot run this action; update it")

// actionAbility checks that the agent reported the ability an action needs
// (such as the persistence report or an indicator hunt).
func (s *Store) actionAbility(ctx context.Context, device string, a protocol.ResponseAction) error {
	need := map[string]string{"persistence": protocol.AbilityPersistence, "hunt": protocol.AbilityHunt, "isolate": protocol.AbilityIsolation, "release": protocol.AbilityIsolation}[a.Kind]
	if need != "" && !s.HasAbility(ctx, device, need) {
		var active int
		if e := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL`, device).Scan(&active); e != nil || active != 1 {
			return ErrEvidence
		}
		return ErrActionUnsupported
	}
	return nil
}

func (s *Store) queueJob(ctx context.Context, caseID, deviceID, source, path, query, action, session, actor string, now time.Time) (string, error) {
	if s.evidence == "" || !protocol.ValidID(deviceID) {
		return "", ErrEvidence
	}
	disabled, e := s.DisabledFeatures(ctx, deviceID)
	if e != nil {
		return "", ErrEvidence
	}
	locks, e := s.FeatureLocks(ctx, deviceID)
	if e != nil || slices.Contains(disabled, "response") || slices.Contains(locks, "response") {
		return "", ErrEvidence
	}
	id, e := evidenceID()
	if e != nil {
		return "", e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return "", errors.New("cannot begin collection")
	}
	defer tx.Rollback()
	var exists, active, device int
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE id=? AND revoked_at IS NULL`, deviceID).Scan(&exists); e != nil || exists != 1 {
		return "", ErrEvidence
	}
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(device_id=? AND parent_id=''),0) FROM evidence_jobs WHERE kind='file' AND hunt_id='' AND status IN ('queued','dispatched','uploading','verifying')`, deviceID).Scan(&active, &device); e != nil || active >= maxActiveEvidence || device >= maxDeviceEvidence {
		return "", ErrEvidence
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO evidence_jobs(id,case_id,device_id,actor,path,status,chunk_size,created_at,expires_at,source,action,session_id,query) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, caseID, deviceID, actor, path, "queued", EvidenceChunk, now.Unix(), now.Add(evidenceQueueLife).Unix(), source, action, session, query); e != nil {
		return "", ErrEvidence
	}
	details, name := map[string]string{"job": id, "path": path}, "collection_requested"
	if source == "hive" {
		details["source"] = "registry hive"
	}
	if source == "evtx" {
		details["source"] = "event log"
		if query != "" {
			details["query"] = query
		}
	}
	if source == "triage" {
		details["source"], details["items"] = "triage package", query
	}
	if action != "" {
		details, name = map[string]string{"job": id, "action": path, "spec": action}, "action_requested"
	}
	if _, e = AppendCustody(ctx, tx, caseID, actor, deviceID, name, details, nil, "success", now); e != nil {
		return "", e
	}
	return id, tx.Commit()
}

// jobAction reads a job's action spec ("" for collections).
func jobAction(ctx context.Context, tx *sql.Tx, job string) string {
	var a string
	_ = tx.QueryRowContext(ctx, `SELECT action FROM evidence_jobs WHERE id=?`, job).Scan(&a)
	return a
}

// custodyName names a job's custody entries: collection_* for files and
// hives, action_* for response actions.
func custodyName(action, suffix string) string {
	if action != "" {
		return "action_" + suffix
	}
	return "collection_" + suffix
}

// DispatchEvidence hands a queued job to its device once, after checking
// again that the requester may still collect from it and that response is
// still on; an upload that has been idle is handed out again for resuming.
func (s *Store) DispatchEvidence(ctx context.Context, device, fp string, now time.Time) (protocol.EvidenceDispatch, error) {
	out := protocol.EvidenceDispatch{}
	// Read before the transaction: the store has a single connection.
	disabled, e := s.DisabledFeatures(ctx, device)
	if e != nil {
		return out, e
	}
	locks, e := s.FeatureLocks(ctx, device)
	if e != nil {
		return out, e
	}
	off := slices.Contains(disabled, "response") || slices.Contains(locks, "response")
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return out, e
	}
	var q protocol.EvidenceJob
	j := EvidenceJob{DeviceID: device}
	// Handed out again: an upload idle long enough to resume, and an action
	// dispatched to an agent that has asked for work again — it restarted,
	// so it uploads a kept result or reports the action as unknown. (An
	// agent ignores a long job it is still running or has queued.) A device
	// gets one search at a time: the next waits until the running one has
	// finished. Isolate and release go first.
	e = tx.QueryRowContext(ctx, `SELECT id,case_id,actor,path,status,chunk_size,source,action,query FROM evidence_jobs WHERE device_id=? AND kind='file' AND ((status='queued' AND expires_at>? AND (hunt_id='' OR NOT EXISTS (SELECT 1 FROM evidence_jobs r WHERE r.device_id=evidence_jobs.device_id AND r.hunt_id<>'' AND r.status IN ('dispatched','uploading','verifying')))) OR (status='uploading' AND activity_at<=?) OR (status='dispatched' AND action!='' AND activity_at<=?)) ORDER BY action NOT LIKE '{"kind":"isolate"%' AND action NOT LIKE '{"kind":"release"%',hunt_id<>'',created_at,id LIMIT 1`, device, now.Unix(), now.Add(-evidenceResume).Unix(), now.Add(-evidenceResume).Unix()).Scan(&j.ID, &j.CaseID, &j.Actor, &j.Path, &j.Status, &j.ChunkSize, &j.Source, &j.Action, &j.Query)
	if errors.Is(e, sql.ErrNoRows) {
		return out, tx.Commit()
	}
	if e != nil {
		return out, e
	}
	var a protocol.ResponseAction
	if j.Action != "" {
		var ok bool
		if a, ok = protocol.ParseAction(j.Action); !ok {
			return out, s.failEvidence(ctx, tx, j, "failed", now)
		}
	}
	// A mutating action handed out before may already have run.
	refused := func(outcome string) string {
		if j.Status != "queued" && a.Mutating() {
			return "unknown"
		}
		return outcome
	}
	if off {
		return out, s.failEvidence(ctx, tx, j, refused("response_off"), now)
	}
	if authorizeActor(ctx, tx, j.Actor, device, "response") != nil {
		return out, s.failEvidence(ctx, tx, j, refused("not_permitted"), now)
	}
	if a.Kind == "drop" && a.Source == "tool" && j.Status == "queued" {
		var withdrawn int
		if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM response_tools WHERE id=? AND withdrawn_at IS NOT NULL`, a.Ref).Scan(&withdrawn); e != nil {
			return out, e
		}
		if withdrawn > 0 {
			return out, s.failEvidence(ctx, tx, j, "withdrawn", now)
		}
	}
	window := evidenceStartWindow
	if j.Source == "evtx" {
		// The whole log is exported before the upload starts.
		window = actionStartWindow
	}
	if j.Source == "triage" {
		// The whole package is read before the upload starts.
		window = triageStartWindow
	}
	if j.Action != "" {
		window = actionStartWindow
		if a.Kind == "drop" {
			// The file is downloaded before the result uploads: allow for a
			// slow link (512 KiB/s).
			window += time.Duration(a.Size/(512<<10)) * time.Second
		}
		if a.Kind == "hunt" {
			// Indicator hunts share the agent's long-job worker with triage
			// packages, so one may wait behind a package.
			window = triageStartWindow + actionStartWindow
		}
	}
	switch j.Status {
	case "queued", "dispatched":
		_, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='dispatched',dispatched_at=?,activity_at=?,expires_at=? WHERE id=? AND status=?`, now.Unix(), now.Unix(), now.Add(window).Unix(), j.ID, j.Status)
	default:
		_, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET activity_at=? WHERE id=? AND status='uploading'`, now.Unix(), j.ID)
	}
	if e != nil {
		return out, e
	}
	q.ID, q.DeviceID, q.Path, q.ChunkSize, q.Resumed = j.ID, device, j.Path, j.ChunkSize, j.Status != "queued"
	if j.Source == "hive" || j.Source == "evtx" || j.Source == "triage" {
		q.Source, q.Query = j.Source, j.Query
	}
	if j.Action != "" {
		q.Source, q.Action = "action", &a
	}
	q.MaxSize, q.ExpiresAt = EvidenceMaxFile, now.Add(window).Unix()
	out.Job = &q
	return out, tx.Commit()
}

// deviceJob loads a device's job for an agent call, after device auth.
func deviceJob(ctx context.Context, tx *sql.Tx, device, fp, job string, now time.Time) (EvidenceJob, error) {
	var j EvidenceJob
	if e := authorizedActionDevice(ctx, tx, device, fp, now); e != nil {
		return j, e
	}
	e := tx.QueryRowContext(ctx, `SELECT id,case_id,device_id,actor,path,status,chunk_size,size,resolved_path,file_modified,file_created,device_sha256,expires_at FROM evidence_jobs WHERE id=? AND device_id=? AND kind='file'`, job, device).Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Actor, &j.Path, &j.Status, &j.ChunkSize, &j.Size, &j.Resolved, &j.FileModified, &j.FileCreated, &j.DeviceSHA256, &j.ExpiresAt)
	if e != nil {
		return j, ErrEvidence
	}
	return j, nil
}

func (s *Store) quotaUsed(ctx context.Context, tx *sql.Tx) (int64, error) {
	var stored, pending int64
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM evidence_files`).Scan(&stored); e != nil {
		return 0, e
	}
	// Kept results of live response without a case count until purged.
	if e := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size),0) FROM evidence_jobs WHERE status IN ('uploading','verifying') OR case_id=? AND status='succeeded'`, LiveCase).Scan(&pending); e != nil {
		return 0, e
	}
	return stored + pending, nil
}

// StartEvidence records the opened file and returns the chunks already held;
// repeating it with the same file details resumes an upload.
func (s *Store) StartEvidence(ctx context.Context, device, fp, job string, v protocol.EvidenceStart, now time.Time) (protocol.EvidenceProgress, error) {
	out := protocol.EvidenceProgress{Received: []int64{}}
	if v.Size < 0 || v.Size > EvidenceMaxFile || len(v.Resolved) > 2048 || !utf8Text(v.Resolved) || v.Meta != nil && !v.Meta.Valid() {
		return out, ErrEvidence
	}
	meta := ""
	if v.Meta != nil {
		b, e := json.Marshal(v.Meta)
		if e != nil || len(b) > 64<<10 {
			return out, ErrEvidence
		}
		meta = string(b)
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	j, e := deviceJob(ctx, tx, device, fp, job, now)
	if e != nil {
		return out, e
	}
	// A resumed upload must be the same content: the same file details and
	// the same reading method and shadow copy (a new copy or a
	// hive saved again may differ even with the same size and time).
	var stored string
	if e = tx.QueryRowContext(ctx, `SELECT meta_json FROM evidence_jobs WHERE id=?`, job).Scan(&stored); e != nil {
		return out, e
	}
	same := j.Size == v.Size && j.Resolved == v.Resolved && j.FileModified == v.Modified && sameSource(stored, meta)
	switch {
	case j.Status == "dispatched" && j.ExpiresAt > now.Unix():
		used, e := s.quotaUsed(ctx, tx)
		if e != nil {
			return out, e
		}
		if s.evidenceQuota > 0 && used+v.Size > s.evidenceQuota {
			if e := s.failEvidence(ctx, tx, j, "quota", now); e != nil {
				return out, e
			}
			return out, ErrEvidence
		}
		if _, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='uploading',size=?,resolved_path=?,file_modified=?,file_created=?,activity_at=?,meta_json=? WHERE id=?`, v.Size, v.Resolved, v.Modified, v.Created, now.Unix(), meta, job); e != nil {
			return out, e
		}
		f, e := os.OpenFile(s.incoming(job), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if e != nil {
			return out, errors.New("cannot create evidence upload")
		}
		f.Close()
	case j.Status == "uploading" && same:
		rows, e := tx.QueryContext(ctx, `SELECT idx FROM evidence_chunks WHERE job_id=? ORDER BY idx`, job)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var i int64
			if rows.Scan(&i) == nil {
				out.Received = append(out.Received, i)
			}
		}
		rows.Close()
		if _, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET activity_at=? WHERE id=?`, now.Unix(), job); e != nil {
			return out, e
		}
	case j.Status == "uploading":
		// The file is no longer the one being uploaded.
		if e := s.failEvidence(ctx, tx, j, "changed", now); e != nil {
			return out, e
		}
		return out, ErrEvidence
	default:
		return out, ErrEvidence
	}
	return out, tx.Commit()
}

// sameSource compares the method and shadow copy of two stored metadata
// texts ("" when the agent sent none).
func sameSource(a, b string) bool {
	var x, y protocol.EvidenceMeta
	if a != "" && json.Unmarshal([]byte(a), &x) != nil || b != "" && json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	// A saved hive or exported log is a new file each time: never resumed.
	return x.Method == y.Method && x.Snapshot == y.Snapshot && (x.Method != "registry_save" && x.Method != "export" && x.Method != "triage" || a == "")
}

func utf8Text(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

func chunkCount(size, chunk int64) int64 { return (size + chunk - 1) / chunk }

// PutEvidenceChunk writes one verified chunk at its offset and records it
// only while the job is still uploading. A repeated chunk with the same hash
// is accepted without writing again; a different hash for a held chunk is
// refused.
func (s *Store) PutEvidenceChunk(ctx context.Context, device, fp, job string, index int64, hash string, body io.Reader, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	j, e := deviceJob(ctx, tx, device, fp, job, now)
	tx.Rollback()
	if e != nil {
		return e
	}
	count := chunkCount(j.Size, j.ChunkSize)
	if j.Status != "uploading" || index < 0 || index >= count || len(hash) != 64 {
		return ErrEvidence
	}
	want := j.ChunkSize
	if index == count-1 {
		want = j.Size - index*j.ChunkSize
	}
	buf := make([]byte, want+1)
	n, e := io.ReadFull(body, buf)
	if e != io.ErrUnexpectedEOF || int64(n) != want {
		return ErrEvidence
	}
	sum := sha256.Sum256(buf[:n])
	if hex.EncodeToString(sum[:]) != hash {
		return ErrEvidence
	}
	var held string
	if e = s.db.QueryRowContext(ctx, `SELECT sha256 FROM evidence_chunks WHERE job_id=? AND idx=?`, job, index).Scan(&held); e == nil {
		if held != hash {
			return ErrEvidence
		}
		_, e = s.db.ExecContext(ctx, `UPDATE evidence_jobs SET activity_at=? WHERE id=? AND status='uploading'`, now.Unix(), job)
		return e
	}
	f, e := os.OpenFile(s.incoming(job), os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("cannot open evidence upload")
	}
	_, e = f.WriteAt(buf[:n], index*j.ChunkSize)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return errors.New("cannot write evidence upload")
	}
	// Recorded only if the job was not cancelled or ended meanwhile.
	result, e := s.db.ExecContext(ctx, `INSERT INTO evidence_chunks(job_id,idx,sha256) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM evidence_jobs WHERE id=? AND status='uploading') ON CONFLICT(job_id,idx) DO NOTHING`, job, index, hash, job)
	if e != nil {
		return errors.New("cannot record evidence chunk")
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrEvidence
	}
	_, e = s.db.ExecContext(ctx, `UPDATE evidence_jobs SET activity_at=? WHERE id=? AND status='uploading'`, now.Unix(), job)
	return e
}

// failEvidence ends a job that is still in the status j was read with, with
// a custody entry, and commits tx. A job that moved on meanwhile is left
// alone.
func (s *Store) failEvidence(ctx context.Context, tx *sql.Tx, j EvidenceJob, outcome string, now time.Time) error {
	status := "failed"
	if outcome == "expired" || outcome == "cancelled" {
		status = outcome
	}
	result, e := tx.ExecContext(ctx, `UPDATE evidence_jobs SET status=?,outcome=?,finished_at=? WHERE id=? AND status=?`, status, outcome, now.Unix(), j.ID, j.Status)
	if e != nil {
		return e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return tx.Rollback()
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM evidence_chunks WHERE job_id=?`, j.ID); e != nil {
		return e
	}
	if _, e := AppendCustody(ctx, tx, j.CaseID, "system", j.DeviceID, custodyName(jobAction(ctx, tx, j.ID), status), map[string]string{"job": j.ID, "path": j.Path, "reason": outcome}, nil, outcome, now); e != nil {
		return e
	}
	if e := tx.Commit(); e != nil {
		return e
	}
	_ = os.Remove(s.incoming(j.ID))
	if j.CaseID == LiveCase {
		_ = os.Remove(s.scratch(j.ID))
	}
	return nil
}

// FinishEvidence ends the upload. A failure outcome ends the job; "ok" with
// every chunk present queues the whole-file verification.
func (s *Store) FinishEvidence(ctx context.Context, device, fp, job string, v protocol.EvidenceFinish, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	j, e := deviceJob(ctx, tx, device, fp, job, now)
	if e != nil {
		return e
	}
	if j.Status != "dispatched" && j.Status != "uploading" {
		if j.Status == "verifying" && v.Outcome == "ok" && v.SHA256 == j.DeviceSHA256 {
			return nil // a repeated finish
		}
		return ErrEvidence
	}
	switch v.Outcome {
	case "denied", "not_found", "too_large", "changed", "failed", "unknown", "no_space":
		return s.failEvidence(ctx, tx, j, v.Outcome, now)
	case "ok":
	default:
		return ErrEvidence
	}
	var chunks int64
	if e = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_chunks WHERE job_id=?`, job).Scan(&chunks); e != nil {
		return e
	}
	if j.Status != "uploading" || v.Size != j.Size || len(v.SHA256) != 64 || chunks != chunkCount(j.Size, j.ChunkSize) {
		return ErrEvidence
	}
	if _, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='verifying',device_sha256=?,activity_at=? WHERE id=?`, v.SHA256, now.Unix(), job); e != nil {
		return e
	}
	return tx.Commit()
}

// VerifyEvidence verifies one finished upload: the whole file's SHA-256 must
// match the device's; the file is then stored by hash and the collection is
// recorded in the case's custody log. A read error is retried; after
// evidenceAttempts failed attempts the job fails. The upload is moved into
// the store before the database commit, so a retry also accepts the stored
// file. It reports whether a job was handled.
func (s *Store) VerifyEvidence(ctx context.Context, now func() time.Time) (bool, error) {
	var j EvidenceJob
	var attempts int
	var meta string
	e := s.db.QueryRowContext(ctx, `SELECT id,case_id,device_id,actor,path,status,size,chunk_size,resolved_path,file_modified,file_created,device_sha256,verify_attempts,source,meta_json,parent_id,action FROM evidence_jobs WHERE status='verifying' ORDER BY verify_attempts,activity_at,id LIMIT 1`).Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Actor, &j.Path, &j.Status, &j.Size, &j.ChunkSize, &j.Resolved, &j.FileModified, &j.FileCreated, &j.DeviceSHA256, &attempts, &j.Source, &meta, &j.ParentID, &j.Action)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	fail := func(outcome string) (bool, error) {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return false, e
		}
		defer tx.Rollback()
		return true, s.failEvidence(ctx, tx, j, outcome, now())
	}
	retry := func() (bool, error) {
		if attempts+1 >= evidenceAttempts {
			return fail("verify_failed")
		}
		_, e := s.db.ExecContext(ctx, `UPDATE evidence_jobs SET verify_attempts=verify_attempts+1 WHERE id=? AND status='verifying'`, j.ID)
		return true, e
	}
	if len(j.DeviceSHA256) != 64 {
		return fail("hash_mismatch")
	}
	target := s.stored(j.DeviceSHA256)
	if j.CaseID == LiveCase {
		target = s.scratch(j.ID)
	}
	source := s.incoming(j.ID)
	if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
		source = target // an earlier attempt stored it before failing to commit
	}
	hash, size, e := hashFile(ctx, source)
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if errors.Is(e, os.ErrNotExist) {
		return fail("missing_upload")
	}
	if e != nil {
		return retry()
	}
	if size != j.Size || hash != j.DeviceSHA256 {
		_ = os.Remove(s.incoming(j.ID))
		return fail("hash_mismatch")
	}
	if source != target {
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return retry()
		}
		// Content already in the store is reused only if it still has its
		// hash; damaged content is replaced by the verified upload.
		keep := false
		if stored, n, err := hashFile(ctx, target); err == nil && stored == hash && n == size {
			keep = true
		}
		if keep {
			_ = os.Remove(source)
		} else {
			_ = os.Chmod(target, 0600)
			if e = os.Rename(source, target); e != nil {
				return retry()
			}
		}
	}
	_ = os.Chmod(target, 0400)
	at := now()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	result, e := tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='succeeded',outcome='ok',server_sha256=?,finished_at=? WHERE id=? AND status='verifying'`, hash, at.Unix(), j.ID)
	if e != nil {
		return false, e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return true, nil
	}
	if j.CaseID != LiveCase {
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO evidence_files(sha256,size,stored_at) VALUES(?,?,?)`, hash, size, at.Unix()); e != nil {
			return false, e
		}
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM evidence_chunks WHERE job_id=?`, j.ID); e != nil {
		return false, e
	}
	details := map[string]string{"job": j.ID, "path": j.Path, "resolved_path": j.Resolved, "requested_by": j.Actor, "device_sha256": j.DeviceSHA256, "server_sha256": hash, "chunks": strconv.FormatInt(chunkCount(j.Size, j.ChunkSize), 10)}
	if j.FileModified > 0 {
		details["file_modified"] = custody.Stamp(time.Unix(0, j.FileModified))
	}
	if j.FileCreated > 0 {
		details["file_created"] = custody.Stamp(time.Unix(0, j.FileCreated))
	}
	var m protocol.EvidenceMeta
	if meta != "" && json.Unmarshal([]byte(meta), &m) == nil {
		metaDetails(m, details)
	}
	if j.Source == "hive" {
		details["source"] = "registry hive"
	}
	if j.Source == "triage" {
		details["source"] = "triage package"
	}
	if j.Source == "evtx" {
		details["source"] = "event log"
		var query string
		if e = tx.QueryRowContext(ctx, `SELECT query FROM evidence_jobs WHERE id=?`, j.ID).Scan(&query); e != nil {
			return false, e
		}
		if query != "" {
			details["query"] = query
		}
	}
	if j.ParentID != "" {
		details["stream_of"] = j.ParentID
	}
	streams, e := streamPlan(ctx, tx, j, m, details)
	if e != nil {
		return false, e
	}
	collected := "evidence_collected"
	if j.Action != "" {
		collected = "action_completed"
		details = actionDetails(j, target, details)
	}
	if _, e = AppendCustody(ctx, tx, j.CaseID, "system", j.DeviceID, collected, details, []custody.Evidence{{SHA256: hash, Size: size, Name: j.Name()}}, "success", at); e != nil {
		return false, e
	}
	if e = queueStreams(ctx, tx, j, streams, at); e != nil {
		return false, e
	}
	return true, tx.Commit()
}

// actionDetails describes a response action's result in its custody entry:
// the action, and for a kill every process it ended or refused.
func actionDetails(j EvidenceJob, stored string, details map[string]string) map[string]string {
	out := map[string]string{"job": j.ID, "action": j.Path, "spec": j.Action, "requested_by": j.Actor, "device_sha256": details["device_sha256"], "server_sha256": details["server_sha256"]}
	a, ok := protocol.ParseAction(j.Action)
	if !ok || !a.Mutating() || j.Size > 8<<20 {
		return out
	}
	b, e := os.ReadFile(stored)
	var r protocol.ActionResult
	if e != nil || json.Unmarshal(b, &r) != nil {
		out["result"] = "unreadable"
		return out
	}
	switch {
	case a.Kind == "kill":
		lines := []string{}
		for _, k := range r.Killed {
			lines = append(lines, strconv.FormatUint(uint64(k.PID), 10)+" "+k.Name+" started "+k.Start+" "+k.Outcome+" "+k.SHA256)
		}
		out["killed"] = strings.Join(lines, "\n")
	case a.Kind == "script" && r.Script != nil:
		out["script_sha256"], out["script_outcome"] = r.Script.SHA256, r.Script.Outcome
		if r.Script.ExitCode != nil {
			out["exit_code"] = strconv.FormatInt(int64(*r.Script.ExitCode), 10)
		}
		if r.Script.Truncated {
			out["output"] = "truncated"
		}
	case a.Kind == "drop" && r.Drop != nil:
		out["drop_outcome"], out["drop_path"], out["drop_sha256"] = r.Drop.Outcome, r.Drop.Path, r.Drop.SHA256
		out["verified"] = strconv.FormatBool(r.Drop.Verified)
		if r.Drop.Replaced {
			out["replaced_sha256"] = r.Drop.ReplacedSHA256
		}
	}
	return out
}

// metaDetails adds what the agent reported to a custody entry.
func metaDetails(m protocol.EvidenceMeta, details map[string]string) {
	details["method"] = m.Method
	if m.Accessed > 0 {
		details["file_accessed"] = custody.Stamp(time.Unix(0, m.Accessed))
	}
	if m.Changed > 0 {
		details["file_changed"] = custody.Stamp(time.Unix(0, m.Changed))
	}
	if m.Attributes != 0 {
		details["attributes"] = "0x" + strconv.FormatUint(uint64(m.Attributes), 16)
	}
	if m.OwnerSID != "" {
		details["owner_sid"] = m.OwnerSID
	}
	if m.Owner != "" {
		details["owner"] = m.Owner
	}
	if m.Snapshot != "" {
		details["shadow_copy"] = m.Snapshot
		details["shadow_copy_at"] = custody.Stamp(time.Unix(0, m.SnapshotAt))
	}
	if len(m.Streams) > 0 {
		lines := make([]string, 0, len(m.Streams))
		for _, s := range m.Streams {
			hash := s.SHA256
			switch {
			case hash != "":
			case s.Size > protocol.SmallStream:
				hash = "not_hashed (larger than 1 MiB; collect it by path)"
			default:
				hash = "unreadable"
			}
			lines = append(lines, s.Name+" "+strconv.FormatInt(s.Size, 10)+" "+hash)
		}
		if m.StreamsMore {
			lines = append(lines, "(more streams not listed)")
		}
		details["streams"] = strings.Join(lines, "\n")
	}
}

// maxStreamCollections bounds the streams of one file collected on their own.
const maxStreamCollections = 16

// streamPlan picks the small alternate data streams of a collected file to
// collect on their own (streams up to 1 MiB), within the
// server's limit of active collections. Streams of a file read from a
// shadow copy are not queued (each would need its own copy); they are
// collected by path when needed. Streams left out are named in details.
func streamPlan(ctx context.Context, tx *sql.Tx, j EvidenceJob, m protocol.EvidenceMeta, details map[string]string) ([]protocol.EvidenceStream, error) {
	if j.Source == "hive" || j.Source == "evtx" || j.Source == "triage" || j.ParentID != "" || strings.Contains(j.Path[2:], ":") || m.Method == "shadow_copy" || j.CaseID == LiveCase {
		return nil, nil
	}
	var active int
	if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_jobs WHERE kind='file' AND hunt_id='' AND status IN ('queued','dispatched','uploading','verifying')`).Scan(&active); e != nil {
		return nil, e
	}
	plan, skipped := []protocol.EvidenceStream{}, []string{}
	for _, st := range m.Streams {
		if st.Size > protocol.SmallStream || st.SHA256 == "" || !ValidEvidencePath(j.Path+":"+st.Name) {
			continue
		}
		if len(plan) == maxStreamCollections || active+len(plan) >= maxActiveEvidence {
			skipped = append(skipped, st.Name)
			continue
		}
		plan = append(plan, st)
	}
	if len(skipped) > 0 {
		details["streams_not_queued"] = strings.Join(skipped, "\n")
	}
	return plan, nil
}

// queueStreams queues the planned streams, requested by the same account
// and recorded in the custody log.
func queueStreams(ctx context.Context, tx *sql.Tx, j EvidenceJob, streams []protocol.EvidenceStream, now time.Time) error {
	for _, st := range streams {
		child := j.Path + ":" + st.Name
		id, e := evidenceID()
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO evidence_jobs(id,case_id,device_id,actor,path,status,chunk_size,created_at,expires_at,parent_id) VALUES(?,?,?,?,?,'queued',?,?,?,?)`, id, j.CaseID, j.DeviceID, j.Actor, child, EvidenceChunk, now.Unix(), now.Add(evidenceQueueLife).Unix(), j.ID); e != nil {
			return e
		}
		if _, e = AppendCustody(ctx, tx, j.CaseID, "system", j.DeviceID, "collection_requested", map[string]string{"job": id, "path": child, "stream_of": j.ID}, nil, "success", now); e != nil {
			return e
		}
	}
	return nil
}

func hashFile(ctx context.Context, path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var n int64
	for {
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}
		k, e := f.Read(buf)
		h.Write(buf[:k])
		n += int64(k)
		if e == io.EOF {
			return hex.EncodeToString(h.Sum(nil)), n, nil
		}
		if e != nil {
			return "", 0, e
		}
	}
}

// SweepEvidence ends jobs that waited, started or stalled too long. Each job
// is re-read in its own transaction, so one that moved on is left alone.
func (s *Store) SweepEvidence(ctx context.Context, now time.Time) error {
	const stale = `kind='file' AND ((status IN ('queued','dispatched') AND expires_at<=?) OR (status='uploading' AND activity_at<=?))`
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM evidence_jobs WHERE `+stale, now.Unix(), now.Add(-evidenceStall).Unix())
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		var j EvidenceJob
		e = tx.QueryRowContext(ctx, `SELECT id,case_id,device_id,path,status,action FROM evidence_jobs WHERE id=? AND (`+stale+`)`, id, now.Unix(), now.Add(-evidenceStall).Unix()).Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Path, &j.Status, &j.Action)
		if errors.Is(e, sql.ErrNoRows) {
			tx.Rollback()
			continue
		}
		if e != nil {
			tx.Rollback()
			return e
		}
		outcome := map[string]string{"queued": "expired", "dispatched": "no_response", "uploading": "stalled"}[j.Status]
		// A kill handed to the device may have run even though no result came.
		if a, ok := protocol.ParseAction(j.Action); ok && a.Mutating() && j.Status != "queued" {
			outcome = "unknown"
		}
		if e = s.failEvidence(ctx, tx, j, outcome, now); e != nil {
			tx.Rollback()
			return e
		}
	}
	return s.purgeLiveResults(ctx, now)
}

// purgeLiveResults removes case-less live response results after 24 hours.
func (s *Store) purgeLiveResults(ctx context.Context, now time.Time) error {
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM evidence_jobs WHERE case_id=? AND status='succeeded' AND finished_at<=?`, LiveCase, now.Add(-liveResultLife).Unix())
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_ = os.Chmod(s.scratch(id), 0600)
		if e := os.Remove(s.scratch(id)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if _, e := s.db.ExecContext(ctx, `UPDATE evidence_jobs SET status='expired',outcome='purged' WHERE id=? AND status='succeeded'`, id); e != nil {
			return e
		}
	}
	// Their audit events are kept for a year (outside the rolling audit trim).
	_, e = s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE action LIKE 'live\_%' ESCAPE '\' AND occurred_at<?`, now.Add(-liveAuditLife).UTC().Format(time.RFC3339Nano))
	return e
}

// EvidenceJobDevice names the device of a case's job (for authorization).
func (s *Store) EvidenceJobDevice(ctx context.Context, caseID, job string) (string, error) {
	var device string
	if e := s.db.QueryRowContext(ctx, `SELECT device_id FROM evidence_jobs WHERE id=? AND case_id=?`, job, caseID).Scan(&device); e != nil {
		return "", ErrEvidence
	}
	return device, nil
}

// CancelEvidence stops a job that has not finished uploading.
func (s *Store) CancelEvidence(ctx context.Context, caseID, job, actor string, now time.Time) error {
	if caseID == LiveCase {
		return ErrEvidence
	}
	return s.cancelJob(ctx, caseID, job, actor, now)
}

// CancelSessionJob cancels a job the actor started in a live response
// session, with or without a case.
func (s *Store) CancelSessionJob(ctx context.Context, session, actor, job string, now time.Time) error {
	caseID, _, e := s.SessionJobCase(ctx, session, actor, job)
	if e != nil {
		return e
	}
	return s.cancelJob(ctx, caseID, job, actor, now)
}

func (s *Store) cancelJob(ctx context.Context, caseID, job, actor string, now time.Time) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var j EvidenceJob
	if e = tx.QueryRowContext(ctx, `SELECT id,case_id,device_id,path,status,action FROM evidence_jobs WHERE id=? AND case_id=? AND kind='file'`, job, caseID).Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Path, &j.Status, &j.Action); e != nil || j.Status != "queued" && j.Status != "dispatched" && j.Status != "uploading" {
		return ErrEvidence
	}
	// An action handed to the device may already be running.
	if j.Action != "" && j.Status != "queued" {
		return ErrEvidence
	}
	if _, e = tx.ExecContext(ctx, `UPDATE evidence_jobs SET status='cancelled',outcome='cancelled',finished_at=? WHERE id=?`, now.Unix(), job); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `DELETE FROM evidence_chunks WHERE job_id=?`, job); e != nil {
		return e
	}
	if _, e = AppendCustody(ctx, tx, caseID, actor, j.DeviceID, custodyName(j.Action, "cancelled"), map[string]string{"job": job, "path": j.Path}, nil, "cancelled", now); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	_ = os.Remove(s.incoming(job))
	return nil
}

// EvidenceJobs lists a case's collections, newest first.
func (s *Store) EvidenceJobs(ctx context.Context, caseID string) ([]EvidenceJob, error) {
	if caseID == LiveCase {
		return []EvidenceJob{}, nil
	}
	return s.listJobs(ctx, `j.case_id=?`, caseID)
}

// SessionJobs lists the jobs a live response session started.
func (s *Store) SessionJobs(ctx context.Context, session, actor string) ([]EvidenceJob, error) {
	return s.listJobs(ctx, `j.session_id=? AND j.actor=?`, session, actor)
}

// SessionJobCase names the case (LiveCase without one) and device of a job
// the actor started in a session.
func (s *Store) SessionJobCase(ctx context.Context, session, actor, job string) (caseID, device string, err error) {
	if e := s.db.QueryRowContext(ctx, `SELECT case_id,device_id FROM evidence_jobs WHERE id=? AND session_id=? AND actor=?`, job, session, actor).Scan(&caseID, &device); e != nil {
		return "", "", ErrEvidence
	}
	return caseID, device, nil
}

func (s *Store) listJobs(ctx context.Context, where string, args ...any) ([]EvidenceJob, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT j.id,j.case_id,j.device_id,COALESCE(d.hostname,''),j.actor,j.path,j.status,j.outcome,j.chunk_size,j.size,(SELECT COUNT(*) FROM evidence_chunks c WHERE c.job_id=j.id),j.resolved_path,j.file_modified,j.file_created,j.device_sha256,j.server_sha256,j.created_at,j.finished_at,j.kind,j.source,j.meta_json,j.parent_id,j.action,j.query
 FROM evidence_jobs j LEFT JOIN devices d ON d.id=j.device_id WHERE `+where+` ORDER BY j.created_at DESC,j.id LIMIT 500`, args...)
	if e != nil {
		return nil, errors.New("cannot list collections")
	}
	defer rows.Close()
	out := []EvidenceJob{}
	for rows.Next() {
		var j EvidenceJob
		var meta string
		if rows.Scan(&j.ID, &j.CaseID, &j.DeviceID, &j.Hostname, &j.Actor, &j.Path, &j.Status, &j.Outcome, &j.ChunkSize, &j.Size, &j.Received, &j.Resolved, &j.FileModified, &j.FileCreated, &j.DeviceSHA256, &j.ServerSHA256, &j.CreatedAt, &j.FinishedAt, &j.Kind, &j.Source, &meta, &j.ParentID, &j.Action, &j.Query) != nil {
			return nil, errors.New("cannot read collection")
		}
		if j.Action != "" {
			j.Source = "action"
		}
		if meta != "" {
			j.Meta = json.RawMessage(meta)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// OpenCaseEvidence opens a collected file for download. With record set (a
// download from the start) the download is recorded in the custody log
// first; later range requests of the same download are not recorded again.
func (s *Store) OpenCaseEvidence(ctx context.Context, caseID, job, actor string, record bool, now time.Time) (*os.File, EvidenceJob, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, EvidenceJob{}, e
	}
	defer tx.Rollback()
	var j EvidenceJob
	if e = tx.QueryRowContext(ctx, `SELECT id,device_id,path,size,server_sha256,kind,source,action FROM evidence_jobs WHERE id=? AND case_id=? AND status='succeeded'`, job, caseID).Scan(&j.ID, &j.DeviceID, &j.Path, &j.Size, &j.ServerSHA256, &j.Kind, &j.Source, &j.Action); e != nil || len(j.ServerSHA256) != 64 {
		return nil, j, ErrEvidence
	}
	path := s.stored(j.ServerSHA256)
	if caseID == LiveCase {
		path = s.scratch(j.ID)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, j, errors.New("the evidence file is missing from the evidence store")
	}
	if i, e := f.Stat(); e != nil || i.Size() != j.Size {
		f.Close()
		return nil, j, errors.New("the stored evidence file does not have its recorded size")
	}
	name := j.Name()
	// A closed case still records who downloaded its evidence.
	if !record {
		return f, j, nil
	}
	if _, e = appendCustodyAnyStatus(ctx, tx, caseID, actor, j.DeviceID, "evidence_downloaded", map[string]string{"job": job}, []custody.Evidence{{SHA256: j.ServerSHA256, Size: j.Size, Name: name}}, "success", now); e != nil {
		f.Close()
		return nil, j, e
	}
	if e = tx.Commit(); e != nil {
		f.Close()
		return nil, j, e
	}
	return f, j, nil
}

// ActiveEvidence counts a case's unfinished collections.
func activeEvidence(ctx context.Context, tx *sql.Tx, caseID string) (int, error) {
	var n int
	e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_jobs WHERE case_id=? AND status IN ('queued','dispatched','uploading','verifying')`, caseID).Scan(&n)
	return n, e
}

// safeName turns a profile name into part of a file name.
func safeName(s string) string {
	b := strings.Builder{}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}
