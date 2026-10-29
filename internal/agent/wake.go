package agent

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The agent holds one request open to the server (protocol.WorkWait) instead
// of every worker asking every few seconds whether it has work. An idle worker
// sleeps until the server says it has work for it, or wakeFallback passes.
// With a server that cannot wait (older than this agent) or while waits fail,
// workers keep their own short intervals.
const (
	wakeFallback = 2 * time.Minute  // an idle worker still checks this often
	wakeRetry    = 10 * time.Minute // asks a server without waits again after this
	idleCheck    = 5 * time.Second  // waits up to this long are a worker's idle check
)

type waker struct {
	active  atomic.Bool
	mu      sync.Mutex
	idle    map[string]time.Time // kind -> idle until
	changed chan struct{}        // closed when a kind becomes idle
	signals map[string]chan struct{}
}

func newWaker() *waker {
	w := &waker{idle: map[string]time.Time{}, changed: make(chan struct{}), signals: map[string]chan struct{}{}}
	for _, k := range protocol.WorkKinds {
		w.signals[k] = make(chan struct{}, 1)
	}
	return w
}

// setIdle marks a kind idle until a time (zero: busy). A kind that becomes
// idle restarts the open wait, so the server knows to watch for it.
func (w *waker) setIdle(kind string, until time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	was := w.idle[kind].After(now)
	if until.After(now) {
		w.idle[kind] = until
	} else {
		delete(w.idle, kind)
	}
	if !was && until.After(now) {
		close(w.changed)
		w.changed = make(chan struct{})
	}
}

func (w *waker) snapshot() ([]string, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	out := []string{}
	for _, k := range protocol.WorkKinds {
		if w.idle[k].After(now) {
			out = append(out, k)
		}
	}
	return out, w.changed
}

func (w *waker) wake(kind string) {
	if c, ok := w.signals[kind]; ok {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}

func (w *waker) wakeAll() {
	for _, k := range protocol.WorkKinds {
		w.wake(k)
	}
}

// take reports and clears a waiting wake for a kind without blocking.
func (w *waker) take(kind string) bool {
	select {
	case <-w.signals[kind]:
		return true
	default:
		return false
	}
}

// waiter is the wait function of one kind's worker: its idle check becomes a
// sleep until woken while the server answers waits.
func (w *waker) waiter(kind string) func(context.Context, time.Duration) bool {
	return func(ctx context.Context, d time.Duration) bool {
		if w == nil || !w.active.Load() || d > idleCheck {
			return waitContext(ctx, d)
		}
		w.setIdle(kind, time.Now().Add(24*time.Hour))
		defer w.setIdle(kind, time.Time{})
		t := time.NewTimer(wakeFallback)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-w.signals[kind]:
			return true
		case <-t.C:
			return true
		}
	}
}

// runWake keeps one work wait open and wakes the workers it names.
func (s *heartbeatSession) runWake(ctx context.Context, w *waker) {
	var pace pacer
	for ctx.Err() == nil {
		idle, changed := w.snapshot()
		if len(idle) == 0 && w.active.Load() {
			// Every worker is busy: nothing to wait for until one is idle.
			select {
			case <-ctx.Done():
				return
			case <-changed:
			case <-time.After(protocol.WorkWaitSeconds * time.Second):
			}
			continue
		}
		call, cancel := context.WithCancel(ctx)
		var restarted atomic.Bool
		go func() {
			for {
				select {
				case <-changed:
					// Only a kind the open wait does not watch needs a new one.
					now, next := w.snapshot()
					for _, k := range now {
						if !slices.Contains(idle, k) {
							restarted.Store(true)
							cancel()
							return
						}
					}
					changed = next
				case <-call.Done():
					return
				}
			}
		}()
		var r protocol.WorkReply
		e := s.callWithTimeout(call, "/api/v1/agent/work", protocol.WorkWait{Idle: idle}, &r, (protocol.WorkWaitSeconds+15)*time.Second)
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case restarted.Load():
			// Let workers that are settling down join before asking again.
			if !waitContext(ctx, 200*time.Millisecond) {
				return
			}
		case e == nil:
			pace.next(nil, 0)
			w.active.Store(true)
			for _, k := range r.Work {
				w.wake(k)
			}
			// Give woken workers a moment to fetch the work before waiting again.
			if len(r.Work) > 0 && !waitContext(ctx, time.Second) {
				return
			}
		case errors.Is(e, ErrRequestRejected):
			// A server without work waits: keep the short intervals.
			w.active.Store(false)
			w.wakeAll()
			if !waitContext(ctx, wakeRetry) {
				return
			}
		default:
			w.active.Store(false)
			w.wakeAll()
			if !waitContext(ctx, pace.next(e, 5*time.Second)) {
				return
			}
		}
	}
}

// desktopRelay lets the agent answer an idle desktop companion itself: it
// asks the agent about twice a second, and the server needs to hear only of
// changes, of a session it should start, and about once a minute.
type desktopRelay struct {
	mu      sync.Mutex
	at      time.Time
	last    desktop.Exchange
	session bool
}

func sameDesktop(a, b desktop.Exchange) bool {
	return a.Ready == b.Ready && a.Peer == b.Peer && slices.Equal(a.Displays, b.Displays)
}

// quiet reports whether an exchange can be answered locally.
func (d *desktopRelay) quiet(w *waker, p desktop.Exchange) bool {
	if w == nil || !w.active.Load() || !p.Ready || p.ID != "" || p.State != "" || len(p.Frame) > 0 {
		if w != nil {
			w.setIdle(protocol.WorkDesktop, time.Time{})
		}
		return false
	}
	d.mu.Lock()
	quiet := !d.session && sameDesktop(d.last, p) && time.Since(d.at) < time.Minute
	d.mu.Unlock()
	w.setIdle(protocol.WorkDesktop, time.Now().Add(3*time.Second))
	return quiet && !w.take(protocol.WorkDesktop)
}

func (d *desktopRelay) forwarded(p desktop.Exchange, r desktop.Reply) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.at, d.last, d.session = time.Now(), p, r.Request != nil
}
