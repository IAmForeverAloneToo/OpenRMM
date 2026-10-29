package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

type Authorize func(context.Context, string, string, time.Time) error
type Audit func(context.Context, string, string, string, string, time.Time) error

// Recorder keeps a session's transcript (terminals opened from a case).
// Write is called with every output chunk, every input as it is
// delivered to the agent ("in") and every queued input discarded when the
// session ends ("dropped"); Finish once when the session ends. Both run while
// the hub is locked, so they must be quick. A Write error ends the session:
// it never continues unrecorded.
type Recorder interface {
	Write(direction string, at time.Time, data []byte) error
	Finish(reason string, at time.Time)
}
type presence struct {
	peer, identity string
	at             time.Time
	long           bool
}
type session struct {
	Request
	device, owner, peer, state                 string
	viewer, agent, input                       time.Time
	output                                     []byte
	base, total, outputSequence, inputSequence uint64
	inputs                                     []Input
	caseID                                     string
	record                                     Recorder
	idle                                       time.Duration
	// active: a live response command ran since the agent's last reply.
	active bool
}
type endedSession struct {
	device, owner, reason string
	at                    time.Time
}
type Hub struct {
	mu        sync.Mutex
	now       func() time.Time
	authorize Authorize
	audit     Audit
	present   map[string]presence
	sessions  map[string]*session
	ended     map[string]endedSession
}

func NewHub(a Authorize, b Audit) *Hub {
	return &Hub{now: time.Now, authorize: a, audit: b, present: map[string]presence{}, sessions: map[string]*session{}, ended: map[string]endedSession{}}
}
func RandomID() (string, error) {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (h *Hub) end(ctx context.Context, s *session, reason string) error {
	delete(h.sessions, s.ID)
	clear(s.output)
	s.output = nil
	if s.record != nil {
		for _, v := range s.inputs {
			_ = s.record.Write("dropped", h.now(), []byte(v.Data))
		}
	}
	s.inputs = nil
	h.ended[s.ID] = endedSession{s.device, s.owner, reason, h.now()}
	if s.record != nil {
		s.record.Finish(reason, h.now())
	}
	for len(h.ended) > 64 {
		oldest := ""
		for id, v := range h.ended {
			if oldest == "" || v.at.Before(h.ended[oldest].at) || v.at.Equal(h.ended[oldest].at) && id < oldest {
				oldest = id
			}
		}
		delete(h.ended, oldest)
	}
	return h.audit(ctx, s.Actor, "terminal_ended", s.device+"/"+s.ID, reason, h.now())
}
func (h *Hub) sweep(ctx context.Context) error {
	now := h.now()
	for id, v := range h.ended {
		if now.Sub(v.at) >= time.Minute || now.Before(v.at) {
			delete(h.ended, id)
		}
	}
	var first error
	for _, s := range h.sessions {
		reason := ""
		switch {
		case !now.Before(time.Unix(s.Expires, 0)):
			reason = "expired"
		case now.Sub(s.viewer) > 15*time.Second:
			reason = "viewer_disconnected"
		case now.Sub(s.agent) > 8*time.Second:
			reason = "agent_disconnected"
		case now.Sub(s.input) > s.idle:
			reason = "idle"
		}
		if reason == "" && h.authorize(ctx, s.device, s.owner, now) != nil {
			reason = "authorization_ended"
		}
		if reason != "" {
			if e := h.end(ctx, s, reason); first == nil {
				first = e
			}
		}
	}
	for id, p := range h.present {
		if now.Sub(p.at) > 8*time.Second {
			delete(h.present, id)
		}
	}
	return first
}

// Waiting is called while the device's agent waits for work with its
// terminal idle: it keeps the device present for new sessions (the agent
// exchanges only when woken) and reports whether the agent should exchange
// now, because a session is starting or the hub has no presence for it.
func (h *Hub) Waiting(device string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	p, ok := h.present[device]
	if ok && now.Sub(p.at) <= 8*time.Second && !now.Before(p.at) {
		p.at = now
		h.present[device] = p
	} else {
		ok = false
	}
	for _, s := range h.sessions {
		if s.device == device && s.state == "starting" {
			return true
		}
	}
	return !ok
}
func (h *Hub) Create(ctx context.Context, device, owner, actor string) (Request, error) {
	return h.CreateRecorded(ctx, device, owner, actor, "", nil)
}

// CreateRecorded starts a session whose transcript is kept by the recorder
// that open returns for the new session ID; a session that cannot be
// recorded is not started.
func (h *Hub) CreateRecorded(ctx context.Context, device, owner, actor, caseID string, open func(session string) (Recorder, error)) (Request, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.sweep(ctx); e != nil {
		return Request{}, e
	}
	if e := h.authorize(ctx, device, owner, h.now()); e != nil {
		return Request{}, e
	}
	p, ok := h.present[device]
	if !ok || len(h.sessions) >= 4 {
		return Request{}, ErrUnavailable
	}
	for _, s := range h.sessions {
		if s.device == device {
			return Request{}, ErrUnavailable
		}
	}
	id, e := RandomID()
	if e != nil {
		return Request{}, e
	}
	r := Request{ID: id, Actor: actor, Identity: p.identity, Expires: h.now().Add(NormalLifetime).Unix()}
	idle := NormalIdle
	// Live response sessions get the long limits when the agent
	// supports them, with or without a case.
	if p.long {
		r.Expires, r.Idle, idle = h.now().Add(LongLifetime).Unix(), int64(LongIdle/time.Second), LongIdle
	}
	var record Recorder
	if open != nil {
		if record, e = open(id); e != nil {
			return Request{}, e
		}
	}
	if e = h.audit(ctx, actor, "terminal_requested", device+"/"+id, "restricted_account", h.now()); e != nil {
		if record != nil {
			record.Finish("audit_failed", h.now())
		}
		return Request{}, e
	}
	now := h.now()
	h.sessions[id] = &session{Request: r, device: device, owner: owner, peer: p.peer, state: "starting", viewer: now, agent: now, input: now, caseID: caseID, record: record, idle: idle}
	return r, nil
}
func (h *Hub) get(ctx context.Context, id, owner string) (*session, error) {
	if e := h.sweep(ctx); e != nil {
		return nil, e
	}
	s := h.sessions[id]
	if s == nil || s.owner != owner {
		return nil, ErrInvalid
	}
	return s, nil
}
func (h *Hub) View(ctx context.Context, id, owner string, after uint64) (View, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return View{}, e
	}
	if after < s.base || after > s.total {
		return View{}, ErrInvalid
	}
	// Acknowledged bytes are erased; only a case-bound session's recorder keeps them.
	n := after - s.base
	clear(s.output[:n])
	s.output = append([]byte(nil), s.output[n:]...)
	s.base = after
	s.viewer = h.now()
	size := min(len(s.output), MaxChunk)
	return View{Request: s.Request, DeviceID: s.device, State: s.state, Offset: s.base + uint64(size), Output: append([]byte(nil), s.output[:size]...), InputSequence: s.inputSequence, CaseID: s.caseID}, nil
}

// Ending records contain metadata only, and require the exact original browser
// owner plus current device authorization. Never disclose them after revocation.
func (h *Hub) EndReason(ctx context.Context, id, owner string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sweep(ctx) != nil {
		return "", false
	}
	v, ok := h.ended[id]
	if !ok || v.owner != owner || h.authorize(ctx, v.device, owner, h.now()) != nil {
		return "", false
	}
	return v.reason, true
}
func (h *Hub) Input(ctx context.Context, id, owner string, v Input) error {
	if !v.Valid() {
		return ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	if s.state != "active" || v.Sequence != s.inputSequence+1 || len(s.inputs) >= 4 {
		return ErrInvalid
	}
	s.inputs = append(s.inputs, v)
	s.inputSequence = v.Sequence
	s.input = h.now()
	return nil
}

// Touch counts a live response command as activity: it resets the
// idle limit here and, with the next reply, on the agent.
func (h *Hub) Touch(ctx context.Context, id, owner string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	s.input, s.active = h.now(), true
	return nil
}

// Session describes a live session for its owner: the device, the case it
// records to ("" without one) and the account that started it.
func (h *Hub) Session(ctx context.Context, id, owner string) (device, caseID, actor string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return "", "", "", e
	}
	return s.device, s.caseID, s.Actor, nil
}

// Attach binds a running session without a case to one: its
// transcript records from now on.
func (h *Hub) Attach(ctx context.Context, id, owner, caseID string, open func(session string) (Recorder, error)) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	if s.caseID != "" || s.record != nil {
		return ErrInvalid
	}
	record, e := open(s.ID)
	if e != nil {
		return e
	}
	s.caseID, s.record = caseID, record
	return nil
}

func (h *Hub) Stop(ctx context.Context, id, owner string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	return h.end(ctx, s, "administrator_stopped")
}
func (h *Hub) Exchange(ctx context.Context, device string, p Exchange) (Reply, error) {
	if !p.Valid() {
		return Reply{}, ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.sweep(ctx); e != nil {
		return Reply{}, e
	}
	if _, ok := h.present[device]; !ok && len(h.present) >= 1000 {
		return Reply{}, ErrUnavailable
	}
	h.present[device] = presence{p.Peer, p.Identity, h.now(), p.Long}
	for _, s := range h.sessions {
		if s.device != device {
			continue
		}
		if p.Peer != s.peer || p.Identity != s.Identity {
			return Reply{}, h.end(ctx, s, "agent_changed")
		}
		if p.ID != "" && p.ID != s.ID {
			return Reply{}, ErrInvalid
		}
		s.agent = h.now()
		if p.ID == s.ID {
			if p.State != "active" {
				return Reply{}, h.end(ctx, s, p.State)
			}
			if s.state == "starting" {
				if e := h.audit(ctx, s.Actor, "terminal_started", device+"/"+s.ID, "restricted_account", h.now()); e != nil {
					_ = h.end(ctx, s, "audit_failed")
					return Reply{}, e
				}
				s.state = "active"
			}
			want := s.outputSequence
			if len(p.Output) > 0 {
				want++
			}
			if p.Sequence != want {
				return Reply{}, h.end(ctx, s, "sequence_error")
			}
			if len(s.output)+len(p.Output) > MaxPending || s.total+uint64(len(p.Output)) > 16*1024*1024 {
				return Reply{}, h.end(ctx, s, "output_limit")
			}
			s.outputSequence = p.Sequence
			s.output = append(s.output, p.Output...)
			s.total += uint64(len(p.Output))
			if s.record != nil && len(p.Output) > 0 && s.record.Write("out", h.now(), p.Output) != nil {
				return Reply{}, h.end(ctx, s, "recording_failed")
			}
		} else if s.state != "starting" {
			return Reply{}, h.end(ctx, s, "agent_reset")
		}
		r := Reply{Request: &s.Request}
		if p.ID == s.ID && p.State == "active" {
			// Deliver queued inputs in order while the encoded reply stays within
			// the agent's response limit; the rest wait for the next exchange.
			n := 0
			for n < len(s.inputs) {
				r.Inputs = s.inputs[:n+1]
				if b, e := json.Marshal(r); n > 0 && (e != nil || len(b) > replyBudget) {
					break
				}
				n++
			}
			r.Inputs = append([]Input(nil), s.inputs[:n]...)
			// A recorded session delivers input only once it is in the transcript.
			for _, v := range r.Inputs {
				if s.record != nil && s.record.Write("in", h.now(), []byte(v.Data)) != nil {
					s.inputs = nil
					return Reply{}, h.end(ctx, s, "recording_failed")
				}
			}
			s.inputs = append([]Input(nil), s.inputs[n:]...)
			r.Active, s.active = s.active, false
		} // consume before transport; never replay ambiguous input
		return r, nil
	}
	return Reply{}, nil
}
func (h *Hub) Close(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		_ = h.end(ctx, s, "server_stopped")
	}
	clear(h.present)
}
func (h *Hub) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.mu.Lock()
			_ = h.sweep(ctx)
			h.mu.Unlock()
		}
	}
}
