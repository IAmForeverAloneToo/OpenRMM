package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSessionOwnershipLiveStreamsAndNoInputReplay(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	allowed := true
	audits := []string{}
	h := NewHub(func(context.Context, string, string, time.Time) error {
		if !allowed {
			return ErrInvalid
		}
		return nil
	}, func(_ context.Context, _, a, _, _ string, _ time.Time) error { audits = append(audits, a); return nil })
	h.now = func() time.Time { return now }
	p := Exchange{Peer: strings.Repeat("a", 32), Identity: "S-1-5-19"}
	if _, e := h.Create(ctx, "device", "owner", "admin"); e != ErrUnavailable {
		t.Fatal("no presence", e)
	}
	_, _ = h.Exchange(ctx, "device", p)
	q, e := h.Create(ctx, "device", "owner", "admin")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Create(ctx, "device", "owner", "admin"); e != ErrUnavailable {
		t.Fatal("parallel device session")
	}
	if _, e = h.View(ctx, q.ID, "foreign", 0); e != ErrInvalid {
		t.Fatal("foreign read")
	}
	if e = h.Input(ctx, q.ID, "owner", Input{1, "hello"}); e != ErrInvalid {
		t.Fatal("input before start")
	}
	r, e := h.Exchange(ctx, "device", p)
	if e != nil || r.Request == nil || r.Request.ID != q.ID {
		t.Fatal("start dispatch")
	}
	p.ID = q.ID
	p.State = "active"
	p.Output = []byte("<script>literal</script>")
	p.Sequence = 1
	_, e = h.Exchange(ctx, "device", p)
	if e != nil {
		t.Fatal(e)
	}
	v, e := h.View(ctx, q.ID, "owner", 0)
	if e != nil || string(v.Output) != string(p.Output) || v.State != "active" {
		t.Fatal("stream", e)
	}
	if e = h.Input(ctx, q.ID, "owner", Input{1, "diagnostic\r"}); e != nil {
		t.Fatal(e)
	}
	if e = h.Input(ctx, q.ID, "owner", Input{1, "duplicate"}); e != ErrInvalid {
		t.Fatal("browser replay")
	}
	p.Output = nil
	r, e = h.Exchange(ctx, "device", p)
	if e != nil || len(r.Inputs) != 1 {
		t.Fatal("input delivery")
	}
	r, e = h.Exchange(ctx, "device", p)
	if e != nil || len(r.Inputs) != 0 {
		t.Fatal("input redelivered")
	}
	v, e = h.View(ctx, q.ID, "owner", v.Offset)
	if e != nil || len(v.Output) != 0 || len(h.sessions[q.ID].output) != 0 {
		t.Fatal("ack did not erase")
	}
	allowed = false
	r, e = h.Exchange(ctx, "device", p)
	if e != nil || r.Request != nil || len(h.sessions) != 0 {
		t.Fatal("revocation", e)
	}
	if strings.Join(audits, ",") != "terminal_requested,terminal_started,terminal_ended" {
		t.Fatal(audits)
	}
}
func TestExpiryDisconnectLimitsAndAuditFailure(t *testing.T) {
	for _, reason := range []string{"hard", "viewer", "agent", "idle", "epoch", "identity", "overrun", "sequence", "audit"} {
		t.Run(reason, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			auditFail := false
			end := ""
			h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(_ context.Context, _, a, _, v string, _ time.Time) error {
				if auditFail {
					return errors.New("audit unavailable")
				}
				if a == "terminal_ended" {
					end = v
				}
				return nil
			})
			h.now = func() time.Time { return now }
			p := Exchange{Peer: strings.Repeat("a", 32), Identity: "S-1-5-19"}
			_, _ = h.Exchange(ctx, "device", p)
			q, e := h.Create(ctx, "device", "owner", "admin")
			if e != nil {
				t.Fatal(e)
			}
			p.ID = q.ID
			p.State = "active"
			if reason != "audit" {
				_, _ = h.Exchange(ctx, "device", p)
			}
			s := h.sessions[q.ID]
			switch reason {
			case "hard":
				s.Expires = now.Unix()
			case "viewer":
				s.viewer = now.Add(-16 * time.Second)
			case "agent":
				s.agent = now.Add(-9 * time.Second)
			case "idle":
				s.input = now.Add(-121 * time.Second)
			case "epoch":
				p.Peer = strings.Repeat("b", 32)
			case "identity":
				p.Identity = "S-1-5-20"
			case "overrun":
				s.output = make([]byte, MaxPending)
				p.Output = []byte("x")
				p.Sequence = 1
			case "sequence":
				p.Sequence = 2
			case "audit":
				auditFail = true
			}
			r, _ := h.Exchange(ctx, "device", p)
			if r.Request != nil || len(h.sessions) != 0 {
				t.Fatal("session survived", reason)
			}
			if reason != "audit" && end == "" {
				t.Fatal("missing end metadata")
			}
		})
	}
}

// While the agent waits for work, the hub keeps the device present (it no
// longer exchanges every second) and asks it to exchange for a new session.
func TestWaitingKeepsPresenceAndAsksForSessions(t *testing.T) {
	ctx := context.Background()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	now := time.Unix(1800000000, 0)
	h.now = func() time.Time { return now }
	if !h.Waiting("dev") {
		t.Fatal("unknown device not asked to exchange")
	}
	if _, e := h.Exchange(ctx, "dev", Exchange{Peer: strings.Repeat("a", 32), Identity: "sid"}); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		now = now.Add(4 * time.Second)
		if h.Waiting("dev") {
			t.Fatal("present device asked to exchange", i)
		}
	}
	if _, e := h.Create(ctx, "dev", "owner", "admin"); e != nil {
		t.Fatal("session refused after 20 s of waiting", e)
	}
	if !h.Waiting("dev") {
		t.Fatal("starting session not signalled")
	}
	now = now.Add(9 * time.Second)
	h2 := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	h2.now = func() time.Time { return now }
	_, _ = h2.Exchange(ctx, "dev", Exchange{Peer: strings.Repeat("a", 32), Identity: "sid"})
	now = now.Add(9 * time.Second)
	if !h2.Waiting("dev") {
		t.Fatal("expired presence kept")
	}
}

func TestGlobalBoundAndProtocolLimits(t *testing.T) {
	ctx := context.Background()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		_, _ = h.Exchange(ctx, id, Exchange{Peer: strings.Repeat(id, 32), Identity: "sid"})
		_, e := h.Create(ctx, id, "owner", "admin")
		if (id == "e") != (e == ErrUnavailable) {
			t.Fatal("global bound", id, e)
		}
	}
	for _, v := range []Input{{0, "x"}, {1, ""}, {1, strings.Repeat("x", MaxInput+1)}, {1, string([]byte{255})}} {
		if v.Valid() {
			t.Fatal("invalid input")
		}
	}
	if (Exchange{Peer: strings.Repeat("a", 32), Identity: "sid", ID: strings.Repeat("b", 32), State: "active", Output: make([]byte, MaxChunk+1), Sequence: 1}).Valid() {
		t.Fatal("output bound")
	}
	h.Close(ctx)
	if len(h.sessions) != 0 || len(h.present) != 0 {
		t.Fatal("close retained data")
	}
}

func TestTerminalEndReasonOwnershipAuthorizationTTLAndBound(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	allowed := true
	h := NewHub(func(context.Context, string, string, time.Time) error {
		if !allowed {
			return ErrInvalid
		}
		return nil
	}, func(context.Context, string, string, string, string, time.Time) error { return nil })
	h.now = func() time.Time { return now }
	p := Exchange{Peer: strings.Repeat("a", 32), Identity: "S-1-5-19"}
	var last string
	for i := 0; i < 66; i++ {
		if _, e := h.Exchange(ctx, "device", p); e != nil {
			t.Fatal(e)
		}
		q, e := h.Create(ctx, "device", "owner", "admin")
		if e != nil {
			t.Fatal(e)
		}
		p.ID, p.State, p.Sequence, p.Output = q.ID, "active", 1, []byte("private output")
		if _, e = h.Exchange(ctx, "device", p); e != nil {
			t.Fatal(e)
		}
		if e = h.Input(ctx, q.ID, "owner", Input{1, "private input"}); e != nil {
			t.Fatal(e)
		}
		s := h.sessions[q.ID]
		if e = h.Stop(ctx, q.ID, "owner"); e != nil {
			t.Fatal(e)
		}
		if len(s.output) != 0 || len(s.inputs) != 0 || len(h.sessions) != 0 {
			t.Fatal("retained live content")
		}
		if reason, ok := h.EndReason(ctx, q.ID, "owner"); !ok || reason != "administrator_stopped" {
			t.Fatal("missing owner ending", reason)
		}
		if _, ok := h.EndReason(ctx, q.ID, "foreign"); ok {
			t.Fatal("foreign ending leak")
		}
		last = q.ID
		p.ID, p.State, p.Sequence, p.Output = "", "", 0, nil
		now = now.Add(time.Millisecond)
	}
	if len(h.ended) != 64 {
		t.Fatal("ending bound", len(h.ended))
	}
	allowed = false
	if _, ok := h.EndReason(ctx, last, "owner"); ok {
		t.Fatal("revoked authorization leak")
	}
	allowed = true
	now = now.Add(time.Minute)
	if _, ok := h.EndReason(ctx, last, "owner"); ok || len(h.ended) != 0 {
		t.Fatal("expired ending retained")
	}
}

// R9: four maximum-size inputs that expand under JSON escaping are split across
// replies (in order, none lost or repeated) so each reply fits an agent's limit.
func TestRepliesStayWithinAgentLimit(t *testing.T) {
	ctx := context.Background()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	p := Exchange{Peer: strings.Repeat("a", 32), Identity: "S-1-5-19"}
	_, _ = h.Exchange(ctx, "device", p)
	q, e := h.Create(ctx, "device", "owner", "admin")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := h.Exchange(ctx, "device", p); e != nil || r.Request == nil {
		t.Fatal("start dispatch", e)
	}
	p.ID, p.State = q.ID, "active"
	if _, e = h.Exchange(ctx, "device", p); e != nil {
		t.Fatal(e)
	}
	for i := uint64(1); i <= 4; i++ {
		if e = h.Input(ctx, q.ID, "owner", Input{i, strings.Repeat("\x01", MaxInput)}); e != nil {
			t.Fatal(e)
		}
	}
	var got []uint64
	for range 6 {
		r, e := h.Exchange(ctx, "device", p)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(r)
		if len(b) > MaxWire {
			t.Fatal("reply exceeds the agent limit", len(b))
		}
		for _, v := range r.Inputs {
			got = append(got, v.Sequence)
		}
	}
	if len(got) != 4 || got[0] != 1 || got[3] != 4 {
		t.Fatal("inputs lost, repeated or reordered", got)
	}
}

type fakeRecorder struct {
	lines []string
	fail  bool
}

func (r *fakeRecorder) Write(direction string, _ time.Time, data []byte) error {
	if r.fail {
		return errors.New("disk full")
	}
	r.lines = append(r.lines, direction+":"+string(data))
	return nil
}
func (r *fakeRecorder) Finish(reason string, _ time.Time) { r.lines = append(r.lines, "end:"+reason) }

// A recorded session passes output, input as it is delivered,
// input dropped at the end and the end itself to the recorder; a session
// that cannot be recorded never starts, and one whose recording fails ends.
func TestRecordedSession(t *testing.T) {
	ctx := context.Background()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	p := Exchange{Peer: strings.Repeat("b", 32), Identity: "S-1-5-18"}
	_, _ = h.Exchange(ctx, "device", p)
	refused := errors.New("no case")
	if _, e := h.CreateRecorded(ctx, "device", "owner", "admin", "case", func(string) (Recorder, error) { return nil, refused }); e != refused || len(h.sessions) != 0 {
		t.Fatal("unrecorded session started", e)
	}
	rec := &fakeRecorder{}
	q, e := h.CreateRecorded(ctx, "device", "owner", "admin", "case", func(id string) (Recorder, error) { rec.lines = append(rec.lines, "open:"+id); return rec, nil })
	if e != nil {
		t.Fatal(e)
	}
	_, _ = h.Exchange(ctx, "device", p)
	p.ID, p.State, p.Sequence, p.Output = q.ID, "active", 1, []byte("PS> ")
	if _, e = h.Exchange(ctx, "device", p); e != nil {
		t.Fatal(e)
	}
	if v, e := h.View(ctx, q.ID, "owner", 0); e != nil || v.CaseID != "case" {
		t.Fatal("view", v, e)
	}
	if e = h.Input(ctx, q.ID, "owner", Input{1, "dir\r"}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(rec.lines, "|"), "in:") {
		t.Fatal("input recorded before delivery")
	}
	p.Output = nil
	if r, e := h.Exchange(ctx, "device", p); e != nil || len(r.Inputs) != 1 {
		t.Fatal("delivery", r, e)
	}
	if e = h.Input(ctx, q.ID, "owner", Input{2, "exit\r"}); e != nil {
		t.Fatal(e)
	}
	if e = h.Stop(ctx, q.ID, "owner"); e != nil {
		t.Fatal(e)
	}
	if got := strings.Join(rec.lines, "|"); got != "open:"+q.ID+"|out:PS> |in:dir\r|dropped:exit\r|end:administrator_stopped" {
		t.Fatal("recorded", got)
	}

	// A failed write ends the session without delivering the input.
	rec = &fakeRecorder{}
	q, _ = h.CreateRecorded(ctx, "device", "owner", "admin", "case", func(string) (Recorder, error) { return rec, nil })
	p = Exchange{Peer: p.Peer, Identity: p.Identity}
	_, _ = h.Exchange(ctx, "device", p)
	p.ID, p.State, p.Sequence = q.ID, "active", 0
	_, _ = h.Exchange(ctx, "device", p)
	_ = h.Input(ctx, q.ID, "owner", Input{1, "whoami\r"})
	rec.fail = true
	if r, _ := h.Exchange(ctx, "device", p); len(r.Inputs) != 0 {
		t.Fatal("unrecorded input delivered")
	}
	if reason, ok := h.EndReason(ctx, q.ID, "owner"); !ok || reason != "recording_failed" {
		t.Fatal("session continued unrecorded", reason)
	}
}

// Long limits (15 minutes idle, 2 hours) come only from an agent that reports
// them; every live response session gets them.
func TestLongSessionLimits(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	h.now = func() time.Time { return now }
	rec := func(string) (Recorder, error) { return &fakeRecorder{}, nil }
	p := Exchange{Peer: strings.Repeat("c", 32), Identity: "S-1-5-18"}
	_, _ = h.Exchange(ctx, "old", p)
	p.Long = true
	_, _ = h.Exchange(ctx, "new", p)
	a, _ := h.CreateRecorded(ctx, "old", "owner", "admin", "case", rec)
	b, _ := h.Create(ctx, "new", "owner", "admin")
	// Every session on a reporting agent gets the long limits.
	if a.Idle != 0 || a.Expires != now.Add(NormalLifetime).Unix() || b.Idle != 900 || b.Expires != now.Add(LongLifetime).Unix() {
		t.Fatal("normal limits", a, b)
	}
	_ = h.Stop(ctx, b.ID, "owner")
	c, _ := h.CreateRecorded(ctx, "new", "owner", "admin", "case", rec)
	if c.Idle != 900 || c.Expires != now.Add(LongLifetime).Unix() {
		t.Fatal("long limits", c)
	}
	// Idle for five minutes ends the normal session but not the long one.
	// The agents and viewers stay connected; nobody types.
	ended := false
	for range 60 {
		now = now.Add(5 * time.Second)
		for _, s := range []Request{a, c} {
			q := p
			q.Long = s.ID == c.ID
			q.ID, q.State = s.ID, "active"
			device := map[bool]string{true: "new", false: "old"}[q.Long]
			_, _ = h.Exchange(ctx, device, q)
			if _, e := h.View(ctx, s.ID, "owner", 0); e != nil && s.ID == a.ID {
				ended = true
			}
		}
	}
	if !ended {
		t.Fatal("normal session outlived its idle limit")
	}
	if _, e := h.View(ctx, c.ID, "owner", 0); e != nil {
		t.Fatal("long session ended early", e)
	}
}

// A live response command counts as activity: it resets the idle
// limit and the next reply tells the agent once.
func TestCommandActivity(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	h := NewHub(func(context.Context, string, string, time.Time) error { return nil }, func(context.Context, string, string, string, string, time.Time) error { return nil })
	h.now = func() time.Time { return now }
	p := Exchange{Peer: strings.Repeat("d", 32), Identity: "S-1-5-18", Long: true}
	_, _ = h.Exchange(ctx, "dev", p)
	s, e := h.Create(ctx, "dev", "owner", "admin")
	if e != nil {
		t.Fatal(e)
	}
	q := p
	q.ID, q.State = s.ID, "active"
	keep := func(minutes int) (active int, err error) {
		for range minutes * 12 {
			now = now.Add(5 * time.Second)
			r, _ := h.Exchange(ctx, "dev", q)
			if r.Active {
				active++
			}
			if _, err = h.View(ctx, s.ID, "owner", 0); err != nil {
				return active, err
			}
		}
		return active, nil
	}
	if _, e = keep(14); e != nil {
		t.Fatal("ended early", e)
	}
	if h.Touch(ctx, s.ID, "other") == nil {
		t.Fatal("another browser session touched the session")
	}
	if e = h.Touch(ctx, s.ID, "owner"); e != nil {
		t.Fatal(e)
	}
	if n, e := keep(14); e != nil || n != 1 {
		t.Fatal("command did not count as activity", n, e)
	}
	if _, e = keep(2); e == nil {
		t.Fatal("idle limit not enforced after the command")
	}
}
