package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// serverUpdates connects the dashboard to the release check and the
// updater sidecar.
type serverUpdates struct {
	dir     string // exchange folder shared with the updater; empty without one
	current serverupdate.Current
	checker serverupdate.Checker

	mu     sync.Mutex
	manual time.Time // last check started from the dashboard
}

const checkEvery = 24 * time.Hour

// check asks for the latest release and stores the result. A failed request
// keeps the release found earlier.
func (u *serverUpdates) check(ctx context.Context, s *storage.Store, now time.Time) error {
	previous, err := s.ServerUpdateSettings(ctx)
	if err != nil {
		return err
	}
	r, e := u.checker.Latest(ctx)
	available, problem := "", ""
	switch {
	case errors.Is(e, serverupdate.ErrNotConfigured):
		problem = "not_configured"
	case errors.Is(e, serverupdate.ErrNoRelease):
		// Only pre-releases (or nothing) so far: nothing to offer, no error.
	case e != nil:
		available, problem = previous.Available, e.Error()
	case !serverupdate.Verify(r, u.current.Keys):
		problem = "The latest release is not signed by a key this server trusts."
	case !serverupdate.Fresh(r.Manifest, now):
		problem = "The latest release has expired."
	case r.Manifest.Sequence > u.current.Sequence:
		b, _ := json.Marshal(r)
		available = string(b)
	}
	return s.RecordServerUpdateCheck(ctx, available, problem, now)
}

// available returns the stored release when it is still newer and valid.
func (u *serverUpdates) available(v storage.ServerUpdateSettings, now time.Time) *serverupdate.Release {
	if v.Available == "" {
		return nil
	}
	var r serverupdate.Release
	if json.Unmarshal([]byte(v.Available), &r) != nil || !u.current.Newer(r, now) {
		return nil
	}
	// Already installed by the updater (its image may carry the same bundled
	// release sequence when only the server changed).
	if st, ok := u.status(); ok && st.Phase == serverupdate.PhaseSucceeded && st.Sequence >= r.Manifest.Sequence {
		return nil
	}
	return &r
}

// status reads the updater's account; ok is false without an updater.
func (u *serverUpdates) status() (serverupdate.Status, bool) {
	if u == nil || u.dir == "" {
		return serverupdate.Status{}, false
	}
	st, e := serverupdate.ReadStatus(u.dir)
	return st, e == nil && st.Present(time.Now())
}

// runServerUpdates checks for releases once a day while the check is on and
// copies the updater's progress into the history.
func runServerUpdates(ctx context.Context, s *storage.Store, u *serverUpdates, logger *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		step, cancel := context.WithTimeout(ctx, time.Minute)
		if st, ok := u.status(); ok && st.ID != "" {
			if e := s.ApplyServerUpdateStatus(step, st.ID, st.Phase, st.Detail, st.Backup, serverupdate.Done(st.Phase), time.Now()); e != nil && ctx.Err() == nil {
				logger.Warn("the server update status could not be recorded")
			}
		}
		if v, e := s.ServerUpdateSettings(step); e == nil && v.CheckEnabled && (v.CheckedAt == nil || time.Since(time.Unix(*v.CheckedAt, 0)) >= checkEvery) {
			if e = u.check(step, s, time.Now()); e != nil && ctx.Err() == nil {
				logger.Warn("the server update check could not be recorded")
			}
		}
		cancel()
	}
}
