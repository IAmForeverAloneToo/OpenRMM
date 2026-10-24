package windowsupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"os"
	"sync"
	"time"
)

type Driver interface {
	Run(context.Context, protocol.UpdateJob, func(protocol.UpdateProgress) error)
}
type record struct {
	Job      protocol.UpdateJob      `json:"job"`
	Created  int64                   `json:"created"`
	Progress protocol.UpdateProgress `json:"progress"`
}
type journal struct {
	Version int      `json:"version"`
	Records []record `json:"records"`
}

// Broker serializes OS mutations independently of agent/server restarts. The
// protected local journal is committed before execution. Interrupted work is
// Unknown on startup and is never resumed or replayed.
type Broker struct {
	mu               sync.Mutex
	path             string
	state            journal
	driver           Driver
	ctx              context.Context
	install, restart bool
	broken           bool
	now              func() time.Time
}

func NewBroker(ctx context.Context, path string, driver Driver, install, restart bool) (*Broker, error) {
	b := &Broker{path: path, state: journal{Version: 1}, driver: driver, ctx: ctx, install: install, restart: restart, now: time.Now}
	f, e := os.Open(path)
	if e == nil {
		info, e := f.Stat()
		if e != nil || info.Size() > 64*1024*1024 {
			f.Close()
			return nil, ErrInvalid
		}
		raw, e := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
		closeErr := f.Close()
		if e != nil || closeErr != nil || len(raw) > 64*1024*1024 {
			return nil, ErrInvalid
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&b.state) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || b.state.Version != 1 || len(b.state.Records) > 100 {
			return nil, ErrInvalid
		}
		seen := map[string]bool{}
		for i := range b.state.Records {
			r := &b.state.Records[i]
			if !JobValid(r.Job) || !ProgressValid(r.Progress, r.Job) || seen[r.Job.ID] {
				return nil, ErrInvalid
			}
			seen[r.Job.ID] = true
			if !Terminal(r.Progress) {
				r.Progress.Phase = "finished"
				r.Progress.Outcome = "unknown"
			}
		}
		if e = b.save(); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	return b, nil
}
func (b *Broker) save() error {
	data, e := json.Marshal(b.state)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(b.path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(b.path+".tmp", b.path)
	}
	return e
}
func initial(q protocol.UpdateJob) protocol.UpdateProgress {
	p := protocol.UpdateProgress{ID: q.ID, Phase: "starting"}
	if q.Action == "install" {
		p.Total = len(q.Updates)
	}
	return p
}
func Failure(q protocol.UpdateJob, outcome string) protocol.UpdateProgress {
	p := initial(q)
	p.Phase = "finished"
	p.Outcome = outcome
	return p
}
func (b *Broker) Handle(r IPCRequest) IPCReply {
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func() IPCReply { return IPCReply{Error: "unavailable"} }
	if b.broken || b.ctx.Err() != nil {
		return fail()
	}
	if r.Op == "probe" && r.Job == nil && r.ID == "" {
		return IPCReply{Support: protocol.UpdateSupport{Broker: "available", CanInstall: b.install, CanRestart: b.restart, Windowed: true}}
	}
	if r.Op == "status" && r.Job == nil && protocol.ValidID(r.ID) {
		for _, v := range b.state.Records {
			if v.Job.ID == r.ID {
				p := v.Progress
				return IPCReply{Progress: &p}
			}
		}
		return IPCReply{Error: "unknown"}
	}
	if r.Op != "submit" || r.Job == nil || r.ID != "" || !JobValid(*r.Job) {
		return IPCReply{Error: "invalid"}
	}
	q := *r.Job
	for _, v := range b.state.Records {
		if v.Job.ID == q.ID {
			a, _ := json.Marshal(v.Job)
			c, _ := json.Marshal(q)
			if string(a) != string(c) {
				return IPCReply{Error: "invalid"}
			}
			p := v.Progress
			return IPCReply{Progress: &p}
		}
	}
	now := b.now()
	if q.ExpiresAt <= now.Unix() || q.ExpiresAt > now.Add(2*time.Minute).Unix() {
		return IPCReply{Error: "expired"}
	}
	if !WindowAllows(q, now) {
		p := Failure(q, "blocked")
		return IPCReply{Progress: &p}
	}
	for _, v := range b.state.Records {
		if !Terminal(v.Progress) {
			return IPCReply{Error: "busy"}
		}
	}
	if (q.Action == "install" && !b.install) || (q.Action == "restart" && !b.restart) {
		p := Failure(q, "denied")
		return IPCReply{Progress: &p}
	}
	if q.Action == "install" {
		var scan *record
		for i := range b.state.Records {
			v := &b.state.Records[i]
			if v.Job.ID == q.ScanID && v.Job.Action == "scan" && v.Progress.Outcome == "ok" && v.Created > now.Add(-2*time.Hour).Unix() && v.Created <= now.Unix() {
				scan = v
			}
		}
		if scan == nil {
			return IPCReply{Error: "stale_scan"}
		}
		for _, selected := range q.Updates {
			found := false
			for _, u := range scan.Progress.Catalog {
				if selected == u.UpdateIdentity && u.Blocked == "" {
					found = true
					break
				}
			}
			if !found {
				return IPCReply{Error: "stale_scan"}
			}
		}
	}
	if len(b.state.Records) >= 100 {
		kept := b.state.Records[:0]
		for _, v := range b.state.Records {
			if v.Created >= now.Add(-2*time.Minute).Unix() || v.Job.ID == q.ScanID || !Terminal(v.Progress) {
				kept = append(kept, v)
			}
		}
		b.state.Records = kept
	}
	if len(b.state.Records) >= 100 {
		return fail()
	}
	p := initial(q)
	b.state.Records = append(b.state.Records, record{q, now.Unix(), p})
	if b.save() != nil {
		b.broken = true
		return fail()
	}
	go b.execute(q)
	return IPCReply{Progress: &p}
}
func (b *Broker) execute(q protocol.UpdateJob) {
	duration := 15 * time.Minute
	if q.Action == "install" {
		duration = 2 * time.Hour
	}
	if q.Action == "restart" {
		duration = time.Minute
	}
	ctx, cancel := context.WithTimeout(b.ctx, duration)
	defer cancel()
	b.driver.Run(ctx, q, func(p protocol.UpdateProgress) error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.broken || !ProgressValid(p, q) {
			return ErrInvalid
		}
		for i := range b.state.Records {
			v := &b.state.Records[i]
			if v.Job.ID == q.ID {
				if Terminal(v.Progress) || p.Completed < v.Progress.Completed {
					return ErrInvalid
				}
				v.Progress = p
				if b.save() != nil {
					b.broken = true
					return ErrInvalid
				}
				return nil
			}
		}
		return ErrInvalid
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.state.Records {
		v := &b.state.Records[i]
		if v.Job.ID == q.ID && !Terminal(v.Progress) {
			v.Progress.Phase = "finished"
			v.Progress.Outcome = "unknown"
			if b.save() != nil {
				b.broken = true
			}
		}
	}
}
