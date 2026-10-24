package isolation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// StateFile is the isolation state in the isolation folder (Dir). It is the
// one source of truth for the agent service and the local break-glass
// command (a separate process run by an administrator): every operation
// takes the folder's lock, reads the file, and replaces it.
const StateFile = "isolation.json"

const lockFile = "isolation.lock"

type stored struct {
	State protocol.IsolationState `json:"state"`
	// Spec is the isolate action in force (with the release code's hash),
	// kept to work the rules out again.
	Spec *protocol.IsolationSpec `json:"spec,omitempty"`
}

// Manager isolates and releases the device.
type Manager struct {
	// Dir is the isolation folder; it must exist.
	Dir      string
	Enforcer Enforcer
	Now      func() time.Time

	mu sync.Mutex
}

// ErrNotIsolated: there is nothing to release.
var ErrNotIsolated = errors.New("the device is not isolated")

// ErrCode: the release code does not match this isolation.
var ErrCode = errors.New("the release code does not match")

// ErrState: the isolation state cannot be read (for the break-glass command:
// usually not run as an administrator, or the wrong -state folder).
var ErrState = errors.New("the isolation state cannot be read; run as an administrator with the agent's -state folder")

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// lock takes the folder's lock file, shared with the other process; a lock
// older than a minute was left by a process that died and is taken over.
func (m *Manager) lock() (func(), error) {
	path := filepath.Join(m.Dir, lockFile)
	for range 100 {
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(e, os.ErrExist) {
			return nil, fmt.Errorf("%w: %v", ErrState, e)
		}
		if i, e := os.Stat(path); e == nil && time.Since(i.ModTime()) > time.Minute {
			_ = os.Remove(path)
			continue
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("the isolation state is busy; try again")
}

// load reads the state; a missing file is "never isolated".
func (m *Manager) load() (stored, error) {
	var v stored
	raw, e := os.ReadFile(filepath.Join(m.Dir, StateFile))
	if errors.Is(e, os.ErrNotExist) {
		return v, nil
	}
	if e != nil {
		return v, fmt.Errorf("%w: %v", ErrState, e)
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &v) != nil || !v.State.Valid() || v.Spec != nil && !v.Spec.Valid() {
		return stored{}, errors.New("the isolation state is damaged")
	}
	return v, nil
}

func (m *Manager) save(v stored) error {
	raw, _ := json.Marshal(v)
	f, e := os.CreateTemp(m.Dir, "isolation-*.tmp")
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if c := f.Close(); e == nil {
		e = c
	}
	if e == nil {
		e = os.Rename(f.Name(), filepath.Join(m.Dir, StateFile))
	}
	if e != nil {
		_ = os.Remove(f.Name())
	}
	return e
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// locked runs f with the in-process and the cross-process lock held.
func (m *Manager) locked(f func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, e := m.lock()
	if e != nil {
		return e
	}
	defer unlock()
	return f()
}

// State reports the isolation; a timed release that is due happens first.
// An unreadable state reports its error.
func (m *Manager) State() protocol.IsolationState {
	var out protocol.IsolationState
	e := m.locked(func() error {
		v, e := m.load()
		if e != nil {
			return e
		}
		out = v.State
		if v.State.Isolated && v.State.ReleaseAt != "" {
			if at, e := time.Parse(time.RFC3339, v.State.ReleaseAt); e == nil && !m.now().Before(at) {
				if r, e := m.release(v, "timed"); e == nil {
					out = r
				}
			}
		}
		return nil
	})
	if e != nil {
		out = protocol.IsolationState{Error: "the isolation state cannot be read"}
	}
	return out
}

// Isolate applies the plan for an isolate action (replacing an isolation in
// force). When the plan cannot be made (no server address) nothing changes.
func (m *Manager) Isolate(job string, spec protocol.IsolationSpec, l Local) (protocol.IsolationState, error) {
	var out protocol.IsolationState
	e := m.locked(func() error {
		prev, _ := m.load()
		rules, e := Plan(spec, l)
		if e != nil {
			out = prev.State
			out.Error = e.Error()
			return e
		}
		SortRules(rules)
		if e = m.Enforcer.Apply(rules); e != nil {
			_ = m.Enforcer.Remove()
			out = prev.State
			out.Error = "the filters could not be applied"
			return e
		}
		now := m.now()
		v := stored{Spec: &spec, State: protocol.IsolationState{Isolated: true, Mode: m.Enforcer.Mode(), Since: stamp(now), Rules: rules, Job: job}}
		if spec.ReleaseAfter > 0 {
			v.State.ReleaseAt = stamp(now.Add(time.Duration(spec.ReleaseAfter) * time.Second))
		}
		if e = m.save(v); e != nil {
			// Never leave filters the agent no longer knows about.
			_ = m.Enforcer.Remove()
			out = protocol.IsolationState{Error: "the isolation state could not be saved"}
			return e
		}
		out = v.State
		return nil
	})
	return out, e
}

// Refresh works the rules out again with what the agent knows now (the
// server's addresses and the resolvers can change) and applies them when
// they changed. A plan that fails keeps the rules in force.
func (m *Manager) Refresh(l Local) error {
	return m.locked(func() error {
		v, e := m.load()
		if e != nil || !v.State.Isolated || v.Spec == nil {
			return e
		}
		rules, e := Plan(*v.Spec, l)
		if e != nil {
			return e
		}
		SortRules(rules)
		if slices.Equal(rules, v.State.Rules) {
			return nil
		}
		if e = m.Enforcer.Apply(rules); e != nil {
			_ = m.Enforcer.Apply(v.State.Rules)
			return e
		}
		v.State.Rules = rules
		return m.save(v)
	})
}

func (m *Manager) release(v stored, how string) (protocol.IsolationState, error) {
	if e := m.Enforcer.Remove(); e != nil {
		return v.State, e
	}
	s := protocol.IsolationState{Released: how, ReleasedAt: stamp(m.now()), Job: v.State.Job}
	if e := m.save(stored{State: s}); e != nil {
		return v.State, e
	}
	return s, nil
}

// Release lifts isolation on the server's request. Releasing a device that
// is not isolated still removes any filters (it is harmless) and succeeds.
func (m *Manager) Release() (protocol.IsolationState, error) {
	var out protocol.IsolationState
	e := m.locked(func() error {
		v, e := m.load()
		if e != nil {
			return e
		}
		out, e = m.release(v, "server")
		return e
	})
	return out, e
}

// BreakGlass lifts isolation locally with the one-time release code shown in
// the dashboard; the next heartbeat reports it.
func (m *Manager) BreakGlass(code string) error {
	return m.locked(func() error {
		v, e := m.load()
		if e != nil {
			return e
		}
		if !v.State.Isolated {
			return ErrNotIsolated
		}
		if v.Spec == nil || !CodeMatches(code, v.Spec.CodeHash) {
			return ErrCode
		}
		_, e = m.release(v, "break_glass")
		return e
	})
}

// Restore applies an isolation in force again when the agent starts (an
// enforcer's filters normally persist across restarts; this repairs them).
func (m *Manager) Restore() error {
	return m.locked(func() error {
		v, e := m.load()
		if e != nil || !v.State.Isolated {
			return e
		}
		return m.Enforcer.Apply(v.State.Rules)
	})
}

// NewEnforcer is the enforcer agents use: dry run until isolation is
// verified on a disposable VM (Enforce).
func NewEnforcer() Enforcer {
	if Enforce {
		return newPlatformEnforcer()
	}
	return &DryRun{}
}
