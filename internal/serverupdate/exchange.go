package serverupdate

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The server and the updater share one small volume and nothing else: the
// server writes request.json, the updater answers in status.json. The
// updater exposes no port and trusts nothing in the request it does not
// verify itself.
const (
	RequestFile = "request.json"
	StatusFile  = "status.json"
)

// Request asks the updater to install a release.
type Request struct {
	ID          string  `json:"id"`
	Release     Release `json:"release"`
	RequestedBy string  `json:"requested_by"`
	RequestedAt int64   `json:"requested_at"`
}

// Phases of an update, in order; the last three are outcomes.
const (
	PhaseAccepted   = "accepted"
	PhasePulling    = "pulling"
	PhaseBackingUp  = "backing_up"
	PhaseStarting   = "starting"
	PhaseSucceeded  = "succeeded"
	PhaseRolledBack = "rolled_back"
	PhaseFailed     = "failed"
)

// Status is the updater's account of the latest request.
type Status struct {
	ID       string `json:"id"`
	Phase    string `json:"phase"`
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	// Detail is a short fixed explanation, never raw Docker output.
	Detail string `json:"detail,omitempty"`
	// Backup names the verified backup taken before the update.
	Backup    string `json:"backup,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
	// Alive is the updater's heartbeat (about once a minute while idle).
	Alive int64 `json:"alive,omitempty"`
	// Updater is present so the server can tell an updater is installed.
	Updater int `json:"updater"`
}

// UpdaterRevision is the exchange format version.
const UpdaterRevision = 1

// Done reports whether a phase is an outcome.
func Done(phase string) bool {
	return phase == PhaseSucceeded || phase == PhaseRolledBack || phase == PhaseFailed
}

func validPhase(p string) bool {
	switch p {
	case PhaseAccepted, PhasePulling, PhaseBackingUp, PhaseStarting, PhaseSucceeded, PhaseRolledBack, PhaseFailed, "idle":
		return true
	}
	return false
}

// writeJSON replaces a file in one step.
func writeJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	_, e1 := f.Write(b)
	e2 := f.Sync()
	e3 := f.Close()
	if e = errors.Join(e1, e2, e3); e == nil {
		e = os.Chmod(tmp, 0600)
	}
	if e == nil {
		e = os.Rename(tmp, path)
	}
	if e != nil {
		_ = os.Remove(tmp)
	}
	return e
}

// openRegular opens a file only if it is a regular file, without following
// a symbolic link or blocking: the server can write the exchange volume and
// the data volume, and must not be able to stall or exhaust the updater.
func openRegular(path string) (*os.File, error) {
	f, e := os.OpenFile(path, openFlags, 0)
	if e != nil {
		return nil, e
	}
	if info, e := f.Stat(); e != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}

func readJSON(path string, v any, limit int) error {
	f, e := openRegular(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil {
		return e
	}
	if len(b) > limit {
		return errors.New("file too large")
	}
	return agentupdate.Decode(b, v)
}

// SubmitRequest hands a request to the updater (server side). It refuses
// while an earlier request is still waiting or running.
func SubmitRequest(dir string, r Request, now time.Time) error {
	if _, e := os.Stat(filepath.Join(dir, RequestFile)); e == nil {
		return ErrBusy
	}
	if s, e := ReadStatus(dir); e == nil && !Done(s.Phase) && s.Phase != "idle" && now.Unix()-s.UpdatedAt < int64(staleAfter/time.Second) {
		return ErrBusy
	}
	return writeJSON(filepath.Join(dir, RequestFile), r)
}

// ErrBusy means an update is already waiting or running.
var ErrBusy = errors.New("an update is already in progress")

// staleAfter: a status that has not moved for this long is from an updater
// that stopped mid-way; the server no longer treats it as running.
const staleAfter = 30 * time.Minute

// Present reports whether the status comes from a running updater: its
// heartbeat is recent, or it is in the middle of an update.
func (s Status) Present(now time.Time) bool {
	if s.Updater <= 0 {
		return false
	}
	last := max(s.Alive, s.UpdatedAt)
	return now.Unix()-last < 5*60 || !Done(s.Phase) && s.Phase != "idle" && now.Unix()-last < int64(staleAfter/time.Second)
}

// ReadStatus returns the updater's status (server side).
func ReadStatus(dir string) (Status, error) {
	var s Status
	if e := readJSON(filepath.Join(dir, StatusFile), &s, 8192); e != nil {
		return Status{}, e
	}
	if !validPhase(s.Phase) || s.ID != "" && !protocol.ValidID(s.ID) || len(s.Detail) > 300 || len(s.Backup) > 100 {
		return Status{}, errors.New("invalid updater status")
	}
	return s, nil
}

func validRequest(r Request) bool {
	return protocol.ValidID(r.ID) && len(r.RequestedBy) <= 128 && r.RequestedAt > 0
}
