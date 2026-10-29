package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type Authorize func(context.Context, string, string, time.Time) error
type Audit func(context.Context, string, string, string, string, time.Time) error
type presence struct {
	peer     string
	at       time.Time
	displays []Display
}
type queued struct {
	input Input
	at    time.Time
}
type session struct {
	Request
	device, owner, peer             string
	state                           string
	created, viewer, agent, frameAt time.Time
	frame                           []byte
	inputs                          []queued
	sequence                        uint64
}
type View struct {
	Request
	DeviceID string    `json:"device_id"`
	State    string    `json:"state"`
	FrameAt  int64     `json:"frame_at"`
	FrameAge int64     `json:"frame_age_ms"`
	Sequence uint64    `json:"sequence"`
	Displays []Display `json:"displays"`
}

// choice checks a display and quality against what the companion reported;
// a companion that reports no displays (before release 30) offers only its
// primary display (index 0).
func choice(p presence, display int, quality string) bool {
	return ValidQuality(quality) && display >= 0 && (display < len(p.displays) || display == 0 && len(p.displays) == 0)
}

// Displays lists what a device's companion can share, for the start dialog.
func (h *Hub) Displays(ctx context.Context, device, owner string) ([]Display, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.sweep(ctx); e != nil {
		return nil, false, e
	}
	if e := h.authorize(ctx, device, owner, h.now()); e != nil {
		return nil, false, e
	}
	p, ok := h.present[device]
	if !ok || p.peer == "" {
		return []Display{}, false, nil
	}
	return append([]Display{}, p.displays...), true, nil
}

// Configure switches a running session's display or quality.
func (h *Hub) Configure(ctx context.Context, id, owner string, display int, quality string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	if !choice(h.present[s.device], display, quality) {
		return ErrInvalid
	}
	s.Display, s.Quality = display, quality
	return nil
}

type endedSession struct {
	device, owner, reason string
	at                    time.Time
}

// Hub deliberately keeps media/input only in bounded memory. A process restart
// has no resumable session. Lifecycle audit writes must succeed before activation.
type Hub struct {
	mu        sync.Mutex
	now       func() time.Time
	authorize Authorize
	audit     Audit
	present   map[string]presence
	sessions  map[string]*session
	ended     map[string]endedSession
}

func NewHub(check Authorize, audit Audit) *Hub {
	return &Hub{now: time.Now, authorize: check, audit: audit, present: make(map[string]presence), sessions: make(map[string]*session), ended: make(map[string]endedSession)}
}
func RandomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (h *Hub) end(ctx context.Context, s *session, reason string) error {
	delete(h.sessions, s.ID)
	s.frame = nil
	s.inputs = nil
	if h.ended == nil {
		h.ended = make(map[string]endedSession)
	}
	h.ended[s.ID] = endedSession{s.device, s.owner, reason, h.now()}
	for len(h.ended) > 64 {
		oldest := ""
		for id, v := range h.ended {
			if oldest == "" || v.at.Before(h.ended[oldest].at) || v.at.Equal(h.ended[oldest].at) && id < oldest {
				oldest = id
			}
		}
		delete(h.ended, oldest)
	}
	return h.audit(ctx, s.Actor, "desktop_ended", s.device+"/"+s.ID, reason, h.now())
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
		case now.Sub(s.viewer) > 30*time.Second:
			reason = "viewer_disconnected"
		case now.Sub(s.agent) > 10*time.Second:
			reason = "agent_disconnected"
		case s.state == "waiting" && now.Sub(s.created) > time.Minute:
			reason = "consent_timeout"
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
		if now.Sub(p.at) > 10*time.Second {
			delete(h.present, id)
		}
	}
	return first
}

// Waiting is called while the device's agent waits for work with its
// companion connected and no session running: it keeps the device present
// for new sessions and reports whether the agent should exchange now,
// because a session is waiting for it or the hub has no presence for it.
func (h *Hub) Waiting(device string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	p, ok := h.present[device]
	if ok && p.peer != "" && now.Sub(p.at) <= 10*time.Second && !now.Before(p.at) {
		p.at = now
		h.present[device] = p
	} else {
		ok = false
	}
	for _, s := range h.sessions {
		if s.device == device {
			return true
		}
	}
	return !ok
}
func (h *Hub) Create(ctx context.Context, device, owner, actor string, control bool, display int, quality string) (Request, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.sweep(ctx); e != nil {
		return Request{}, e
	}
	now := h.now()
	if e := h.authorize(ctx, device, owner, now); e != nil {
		return Request{}, e
	}
	p, ok := h.present[device]
	if !ok || p.peer == "" || len(h.sessions) >= 4 {
		return Request{}, ErrUnavailable
	}
	if !choice(p, display, quality) {
		return Request{}, ErrInvalid
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
	r := Request{ID: id, Actor: actor, Control: control, Expires: now.Add(15 * time.Minute).Unix(), Display: display, Quality: quality}
	if e = h.audit(ctx, actor, "desktop_requested", device+"/"+id, map[bool]string{true: "control", false: "view"}[control], now); e != nil {
		return Request{}, e
	}
	h.sessions[id] = &session{Request: r, device: device, owner: owner, peer: p.peer, state: "waiting", created: now, viewer: now, agent: now}
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
func (h *Hub) View(ctx context.Context, id, owner string) (View, []byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return View{}, nil, e
	}
	s.viewer = h.now()
	v := View{Request: s.Request, DeviceID: s.device, State: s.state, Sequence: s.sequence, Displays: append([]Display{}, h.present[s.device].displays...)}
	if !s.frameAt.IsZero() {
		v.FrameAt = s.frameAt.UnixMilli()
		v.FrameAge = h.now().Sub(s.frameAt).Milliseconds()
	}
	// Never return an old screenshot as a live screen after an agent stall.
	if h.now().Sub(s.frameAt) > 3*time.Second {
		return v, nil, nil
	}
	return v, append([]byte(nil), s.frame...), nil
}

// Fixed end reasons, without media/input, last at most one minute in memory.
// Exact browser ownership and current device authorization still apply.
func (h *Hub) EndReason(ctx context.Context, id, owner string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v, ok := h.ended[id]
	if !ok || v.owner != owner || h.now().Sub(v.at) >= time.Minute || h.now().Before(v.at) || h.authorize(ctx, v.device, owner, h.now()) != nil {
		return ""
	}
	return v.reason
}
func (h *Hub) Input(ctx context.Context, id, owner string, b Batch) error {
	if !b.Valid() {
		return ErrInvalid
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	if !s.Control || s.state != "active" || h.now().Sub(s.frameAt) > 3*time.Second || b.Sequence <= s.sequence || len(s.inputs)+len(b.Events) > 64 {
		return ErrInvalid
	}
	s.sequence = b.Sequence
	for _, v := range b.Events {
		s.inputs = append(s.inputs, queued{v, h.now()})
	}
	return nil
}
func (h *Hub) Stop(ctx context.Context, id, owner string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, e := h.get(ctx, id, owner)
	if e != nil {
		return e
	}
	return h.end(ctx, s, "viewer_stopped")
}

func (h *Hub) Close(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.sessions {
		_ = h.end(ctx, s, "server_stopped")
	}
	clear(h.present)
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
	if p.Ready {
		if _, ok := h.present[device]; !ok && len(h.present) >= 1000 {
			return Reply{}, ErrUnavailable
		}
		h.present[device] = presence{p.Peer, h.now(), p.Displays}
	} else {
		delete(h.present, device)
	}
	for _, s := range h.sessions {
		if s.device != device {
			continue
		}
		if !p.Ready || s.peer != p.Peer {
			return Reply{}, h.end(ctx, s, "companion_disconnected")
		}
		s.agent = h.now()
		if p.ID != "" && p.ID != s.ID {
			return Reply{}, ErrInvalid
		}
		if p.ID == s.ID {
			switch p.State {
			case "denied", "ended", "unavailable":
				return Reply{}, h.end(ctx, s, p.State)
			case "active":
				if s.state == "waiting" {
					if e := h.audit(ctx, s.Actor, "desktop_consented", device+"/"+s.ID, "success", h.now()); e != nil {
						_ = h.end(ctx, s, "audit_failed")
						return Reply{}, e
					}
					s.state = "active"
				}
				if len(p.Frame) > 0 {
					s.frame = append(s.frame[:0], p.Frame...)
					s.frameAt = h.now()
				}
			case "waiting":
				if s.state != "waiting" {
					return Reply{}, h.end(ctx, s, "companion_reset")
				}
			}
		}
		r := Reply{Request: &s.Request}
		if s.state == "active" && p.ID == s.ID && p.State == "active" {
			for _, q := range s.inputs {
				if h.now().Sub(q.at) <= time.Second {
					r.Inputs = append(r.Inputs, q.input)
				}
			}
			// Consume before transport: ambiguous delivery never replays input.
			s.inputs = nil
		}
		return r, nil
	}
	return Reply{}, nil
}

// Run expires sessions even when all network peers disappear.
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
