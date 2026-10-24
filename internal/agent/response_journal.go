package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The response journal is the agent's durable record of response
// jobs it started and finished, kept in its private state folder across
// restarts and updates. A job is run at most once: a finished job that is
// dispatched again is never executed again, its recorded result is sent
// again instead (the server may have missed it). A started job may be
// resumed only when its kind allows it (evidence uploads do).

const (
	responseJournalFile = "response-journal.json"
	journalRetention    = 30 * 24 * time.Hour
	journalLimit        = 10000
)

type journalEntry struct {
	Kind    string          `json:"kind"`
	State   string          `json:"state"` // started or finished
	At      int64           `json:"at"`
	Result  json.RawMessage `json:"result,omitempty"`
	Resumes int             `json:"resumes,omitempty"`
}

type responseJournal struct {
	mu      sync.Mutex
	path    string
	entries map[string]journalEntry
}

var errJournal = errors.New("the response journal cannot be read or written")

// openJournal reads the journal; a missing file is an empty journal, an
// unreadable or invalid one stops response work rather than risk a replay.
func openJournal(state string) (*responseJournal, error) {
	j := &responseJournal{path: filepath.Join(state, responseJournalFile), entries: map[string]journalEntry{}}
	b, e := readLimited(j.path, 16<<20)
	if errors.Is(e, os.ErrNotExist) || e != nil && !fileExists(j.path) {
		return j, nil
	}
	if e != nil {
		return nil, errJournal
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&j.entries) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return nil, errJournal
	}
	for id, v := range j.entries {
		if !protocol.ValidID(id) || v.State != "started" && v.State != "finished" {
			return nil, errJournal
		}
	}
	return j, nil
}

func fileExists(p string) bool { _, e := os.Stat(p); return e == nil }

// save writes the journal atomically, dropping old and excess entries.
func (j *responseJournal) save(now time.Time) error {
	ids := make([]string, 0, len(j.entries))
	for id, v := range j.entries {
		if now.Sub(time.Unix(v.At, 0)) > journalRetention {
			delete(j.entries, id)
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) > journalLimit {
		sort.Slice(ids, func(a, b int) bool { return j.entries[ids[a]].At < j.entries[ids[b]].At })
		for _, id := range ids[:len(ids)-journalLimit] {
			delete(j.entries, id)
		}
	}
	b, e := json.Marshal(j.entries)
	if e != nil {
		return errJournal
	}
	f, e := os.CreateTemp(filepath.Dir(j.path), ".response-journal-*")
	if e != nil {
		return errJournal
	}
	name := f.Name()
	defer os.Remove(name)
	_, we := f.Write(b)
	se := f.Sync()
	ce := f.Close()
	if we != nil || se != nil || ce != nil || os.Rename(name, j.path) != nil {
		return errJournal
	}
	return nil
}

// begin records that a job starts. It returns the earlier entry when the job
// was seen before: finished (send its result again) or started (resume when
// resumable, otherwise refuse).
func (j *responseJournal) begin(id, kind string, resumable bool, now time.Time) (journalEntry, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if v, ok := j.entries[id]; ok {
		if v.Kind != kind || v.State == "started" && !resumable {
			return v, true, errJournal
		}
		if v.State == "started" {
			v.Resumes++
			j.entries[id] = v
			if e := j.save(now); e != nil {
				return v, true, e
			}
		}
		return v, true, nil
	}
	j.entries[id] = journalEntry{Kind: kind, State: "started", At: now.Unix()}
	return journalEntry{}, false, j.save(now)
}

// finish records a job's result before it is sent to the server.
func (j *responseJournal) finish(id string, result any, now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, e := json.Marshal(result)
	if e != nil {
		return errJournal
	}
	v := j.entries[id]
	v.State, v.At, v.Result = "finished", now.Unix(), b
	j.entries[id] = v
	return j.save(now)
}
