package devices

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// ErrWork is an invalid wait request.
var ErrWork = errors.New("invalid work wait")

// workSignals wakes waiting agents when the dashboard changed something: for
// one device, or for all (fleet operations). Waiters then check the database
// once; work queued by the server's own schedulers is found by a periodic
// check instead.
type workSignals struct {
	mu  sync.Mutex
	all chan struct{}
	one map[string]chan struct{}
}

func (w *workSignals) watch(device string) (<-chan struct{}, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.all == nil {
		w.all, w.one = make(chan struct{}), map[string]chan struct{}{}
	}
	c, ok := w.one[device]
	if !ok {
		c = make(chan struct{})
		w.one[device] = c
	}
	return w.all, c
}

func (w *workSignals) notify(device string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.all == nil {
		return // nobody has waited yet
	}
	if device == "" {
		close(w.all)
		w.all = make(chan struct{})
		return
	}
	if c, ok := w.one[device]; ok {
		close(c)
		delete(w.one, device)
	}
}

// Notify wakes the agent of a device waiting for work, or every waiting agent
// when device is empty, so it checks for new work at once.
func (s *Service) Notify(device string) { s.work.notify(device) }

const (
	presenceTick   = 4 * time.Second  // keeps terminal and desktop presence (8 and 10 s) fresh
	workCheckEvery = 12 * time.Second // finds work the server's schedulers queued
)

// WaitWork holds an agent's request until the server has work for one of the
// kinds whose workers are idle, or protocol.WorkWaitSeconds pass.
func (s *Service) WaitWork(ctx context.Context, state *tls.ConnectionState, in protocol.WorkWait) (protocol.WorkReply, error) {
	out := protocol.WorkReply{Work: []string{}}
	if !in.Valid() {
		return out, ErrWork
	}
	d, err := s.Authenticate(ctx, state)
	if err != nil || len(in.Idle) == 0 {
		// Nothing idle: answered at once, which also tells the agent that
		// this server holds waits.
		return out, err
	}
	hold := protocol.WorkWaitSeconds * time.Second
	if s.workHold > 0 {
		hold = s.workHold
	}
	deadline := time.NewTimer(hold)
	defer deadline.Stop()
	tick := time.NewTicker(presenceTick)
	defer tick.Stop()
	var checked time.Time
	check := true
	for {
		all, one := s.work.watch(d.ID)
		if slices.Contains(in.Idle, protocol.WorkTerminal) && s.Terminal.Waiting(d.ID) {
			out.Work = append(out.Work, protocol.WorkTerminal)
		}
		if slices.Contains(in.Idle, protocol.WorkDesktop) && s.Desktop.Waiting(d.ID) {
			out.Work = append(out.Work, protocol.WorkDesktop)
		}
		if check || time.Since(checked) >= workCheckEvery {
			kinds, e := s.store.PendingWork(ctx, d.ID, in.Idle)
			if e != nil {
				return out, e
			}
			out.Work = append(out.Work, kinds...)
			checked, check = time.Now(), false
		}
		if len(out.Work) > 0 {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		case <-deadline.C:
			return out, nil
		case <-all:
			check = true
		case <-one:
			check = true
		case <-tick.C:
		}
	}
}
