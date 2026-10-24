package agent

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
	"time"
)

func (s *heartbeatSession) terminalExchange(ctx context.Context, p terminal.Exchange) (terminal.Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var r terminal.Reply
	e := s.call(ctx, "/api/v1/agent/terminal", p, &r)
	return r, e
}

// An error destroys this connection epoch and shell. No input or start request
// is retried; a fresh peer causes the server to retire any ambiguous old session.
func runTerminal(ctx context.Context, state string, exchange func(context.Context, terminal.Exchange) (terminal.Reply, error), start func(string) (terminal.Shell, error), identity string, allowed func() bool) {
	peer, e := terminal.RandomID()
	if e != nil {
		return
	}
	var active terminal.Shell
	var request *terminal.Request
	var seq, inputSequence uint64
	var deadline time.Time
	var lastInput time.Time
	idle := terminal.NormalIdle
	defer func() {
		if active != nil {
			active.Close()
		}
	}()
	// abandon ends this connection epoch after an invalid reply: the shell is
	// closed, nothing is replayed, and a fresh peer starts over after a pause.
	abandon := func() bool {
		if active != nil {
			active.Close()
			active = nil
		}
		request = nil
		seq = 0
		peer, e = terminal.RandomID()
		return e == nil
	}
	var pace pacer
	for ctx.Err() == nil {
		if !allowed() {
			if active != nil {
				active.Close()
				active = nil
			}
			if request != nil {
				request = nil
				peer, e = terminal.RandomID()
				if e != nil {
					return
				}
			}
			if !waitContext(ctx, time.Second) {
				return
			}
			continue
		}
		p := terminal.Exchange{Peer: peer, Identity: identity, Long: true}
		if request != nil {
			if active != nil && (!time.Now().Before(deadline) || time.Since(lastInput) > idle) {
				active.Close()
				active = nil
			}
			p.ID = request.ID
			p.State = "ended"
			p.Sequence = seq
			if active != nil {
				b, done := active.Drain()
				if len(b) > 0 {
					seq++
				}
				p.Sequence = seq
				p.Output = b
				p.State = "active"
				if done {
					p.State = "ended"
					active.Close()
					active = nil
				}
			}
		}
		r, err := exchange(ctx, p)
		if err != nil || r.Request == nil || (request != nil && r.Request.ID != request.ID) {
			if active != nil {
				active.Close()
				active = nil
			}
			request = nil
			seq = 0
			if err != nil {
				peer, e = terminal.RandomID()
				if e != nil {
					return
				}
			}
		}
		if err == nil && r.Request != nil {
			q := r.Request
			if !validTerminalRequest(q, identity) || len(r.Inputs) > 4 || request == nil && len(r.Inputs) != 0 {
				err = errInvalidDispatch
				if !abandon() {
					return
				}
			} else if request == nil {
				request = q
				seq = 0
				inputSequence = 0
				lastInput = time.Now()
				lifetime := terminal.NormalLifetime
				idle = terminal.NormalIdle
				if q.Idle > 0 {
					idle, lifetime = time.Duration(q.Idle)*time.Second, terminal.LongLifetime
				}
				deadline = time.Now().Add(min(time.Until(time.Unix(q.Expires, 0)), lifetime))
				active, e = start(state)
				if e != nil {
					active = nil
				}
			} else if active != nil {
				if r.Active {
					lastInput = time.Now()
				}
				for _, v := range r.Inputs {
					if !allowed() || !v.Valid() || v.Sequence != inputSequence+1 {
						err = errInvalidDispatch
						if !abandon() {
							return
						}
						break
					}
					inputSequence = v.Sequence
					lastInput = time.Now()
					// A blocked native input pipe cannot prevent disconnection enforcement.
					done := make(chan error, 1)
					shell := active
					go func() { done <- shell.Input([]byte(v.Data)) }()
					select {
					case e = <-done:
					case <-time.After(2 * time.Second):
						e = terminal.ErrUnavailable
					case <-ctx.Done():
						e = ctx.Err()
					}
					if e != nil {
						active.Close()
						active = nil
						break
					}
				}
			}
		}
		delay := 250 * time.Millisecond
		if request == nil {
			delay = pace.next(err, time.Second)
		}
		if !waitContext(ctx, delay) {
			return
		}
	}
}

// A normal session lasts at most 15 minutes; a long (recorded) one names its
// idle limit, at most 15 minutes, and lasts at most two hours.
func validTerminalRequest(q *terminal.Request, identity string) bool {
	lifetime := terminal.NormalLifetime
	if q != nil && q.Idle != 0 {
		if q.Idle < 0 || q.Idle > int64(terminal.LongIdle/time.Second) {
			return false
		}
		lifetime = terminal.LongLifetime
	}
	return q != nil && protocol.ValidID(q.ID) && q.Identity == identity && q.Expires > time.Now().Unix() && q.Expires <= time.Now().Add(lifetime+time.Minute).Unix() && len(q.Actor) > 0 && len(q.Actor) <= 184
}
