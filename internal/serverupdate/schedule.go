package serverupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Backups through the exchange volume: the server writes the schedule and
// "back up now" requests, the updater answers with a report. Neither file
// can make the updater do anything but take a backup.
const (
	ScheduleFile      = "backup-schedule.json"
	BackupRequestFile = "backup-request.json"
	BackupReportFile  = "backups.json"
)

// BackupSchedule is the nightly backup time set in the dashboard.
type BackupSchedule struct {
	Enabled bool `json:"enabled"`
	Hour    int  `json:"hour"` // UTC
}

// DefaultSchedule applies until the server has written one.
var DefaultSchedule = BackupSchedule{Enabled: true, Hour: 3}

// BackupRequest asks for a backup now.
type BackupRequest struct {
	ID          string `json:"id"`
	RequestedBy string `json:"requested_by"`
	RequestedAt int64  `json:"requested_at"`
}

// BackupRun is the outcome of the latest backup attempt.
type BackupRun struct {
	ID         string `json:"id,omitempty"` // the dashboard request, if any
	Kind       string `json:"kind"`
	Name       string `json:"name,omitempty"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at,omitempty"`
	OK         bool   `json:"ok"`
	Detail     string `json:"detail,omitempty"`
}

// BackupReport is the updater's account of backups for the dashboard.
type BackupReport struct {
	Updater   int            `json:"updater"`
	UpdatedAt int64          `json:"updated_at"`
	Schedule  BackupSchedule `json:"schedule"`
	NextAt    int64          `json:"next_at,omitempty"`
	Running   *BackupRun     `json:"running,omitempty"`
	Last      *BackupRun     `json:"last,omitempty"`
	Backups   []BackupInfo   `json:"backups"`
}

// WriteSchedule hands the schedule to the updater (server side).
func WriteSchedule(dir string, s BackupSchedule) error {
	if s.Hour < 0 || s.Hour > 23 {
		return errors.New("invalid backup hour")
	}
	return writeJSON(filepath.Join(dir, ScheduleFile), s)
}

// SubmitBackupRequest asks the updater for a backup (server side); it
// refuses while one is waiting.
func SubmitBackupRequest(dir string, r BackupRequest) error {
	if _, e := os.Stat(filepath.Join(dir, BackupRequestFile)); e == nil {
		return ErrBusy
	}
	return writeJSON(filepath.Join(dir, BackupRequestFile), r)
}

// ReadBackupReport returns the updater's backup report (server side).
func ReadBackupReport(dir string) (BackupReport, error) {
	var r BackupReport
	if e := readJSON(filepath.Join(dir, BackupReportFile), &r, 256*1024); e != nil {
		return BackupReport{}, e
	}
	valid := func(run *BackupRun) bool {
		return run == nil || (run.ID == "" || protocol.ValidID(run.ID)) && keepKinds[run.Kind] > 0 && (run.Name == "" || ValidBackupName(run.Name)) && len(run.Detail) <= 300
	}
	if r.Updater <= 0 || r.Schedule.Hour < 0 || r.Schedule.Hour > 23 || !valid(r.Running) || !valid(r.Last) || len(r.Backups) > 100 {
		return BackupReport{}, errors.New("invalid backup report")
	}
	for _, b := range r.Backups {
		if !ValidBackupName(b.Name) || len(b.InstanceID) > 64 {
			return BackupReport{}, errors.New("invalid backup report")
		}
	}
	if r.Backups == nil {
		r.Backups = []BackupInfo{}
	}
	return r, nil
}

// slot is the most recent scheduled time at or before now.
func (s BackupSchedule) slot(now time.Time) time.Time {
	now = now.UTC()
	t := time.Date(now.Year(), now.Month(), now.Day(), s.Hour, 0, 0, 0, time.UTC)
	if t.After(now) {
		t = t.AddDate(0, 0, -1)
	}
	return t
}

func (u *Updater) schedule() BackupSchedule {
	var s BackupSchedule
	if e := readJSON(filepath.Join(u.Dir, ScheduleFile), &s, 1024); e != nil || s.Hour < 0 || s.Hour > 23 {
		return DefaultSchedule
	}
	return s
}

// backups runs a requested backup, or the nightly one when it is due, and
// keeps the report current. A failed nightly backup is tried again after an
// hour.
func (u *Updater) backups(ctx context.Context) {
	if j, e := u.load(); e != nil || j.Active != nil {
		return
	}
	var r BackupRequest
	path := filepath.Join(u.Dir, BackupRequestFile)
	if e := readJSON(path, &r, 4096); !errors.Is(e, os.ErrNotExist) {
		_ = os.Remove(path)
		if e == nil && protocol.ValidID(r.ID) {
			u.backup(ctx, "manual", r.ID)
			return
		}
	}
	s := u.schedule()
	now := u.now()
	slot := s.slot(now)
	// A new server has no database until it has started once.
	if u.Backups.Inspect != nil {
		if _, _, e := u.Backups.Inspect(filepath.Join(u.Backups.Sources["data"], filepath.FromSlash(u.Backups.DB))); e != nil {
			return
		}
	}
	if !s.Enabled || u.lastNightly() >= slot.Unix() || u.lastRun != nil && u.lastRun.Kind == "nightly" && !u.lastRun.OK && now.Sub(time.Unix(u.lastRun.StartedAt, 0)) < time.Hour {
		return
	}
	u.backup(ctx, "nightly", "")
}

func (u *Updater) lastNightly() int64 {
	list, _ := u.Backups.List()
	for _, b := range list {
		if b.Kind == "nightly" {
			return b.CreatedAt
		}
	}
	return 0
}

func (u *Updater) backup(ctx context.Context, kind, id string) {
	run := &BackupRun{ID: id, Kind: kind, StartedAt: u.now().Unix()}
	u.running = run
	u.report()
	name := NewBackupName(kind, u.now())
	e := u.Backups.CreateLive(name)
	run.FinishedAt = u.now().Unix()
	if e != nil {
		u.logf("backup failed", "kind", kind, "error", e.Error())
		run.Detail = "The backup could not be completed or verified; see the updater log."
	} else {
		run.OK, run.Name = true, name
		if e = u.Backups.Prune(); e != nil {
			u.logf("cannot prune old backups", "error", e.Error())
		}
		u.logf("backup taken", "name", name)
	}
	u.running, u.lastRun = nil, run
	u.report()
}

// report writes the backup report for the dashboard.
func (u *Updater) report() {
	s := u.schedule()
	r := BackupReport{Updater: UpdaterRevision, UpdatedAt: u.now().Unix(), Schedule: s, Running: u.running, Last: u.lastRun}
	if s.Enabled {
		r.NextAt = s.slot(u.now()).AddDate(0, 0, 1).Unix()
	}
	list, e := u.Backups.List()
	if e != nil {
		u.logf("cannot list backups", "error", e.Error())
	}
	r.Backups = list
	if e = writeJSON(filepath.Join(u.Dir, BackupReportFile), r); e != nil {
		u.logf("cannot write the backup report", "error", e.Error())
	}
}
