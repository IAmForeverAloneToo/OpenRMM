// Package sessions reports the signed-in Windows sessions: user,
// domain, state, console or remote connection, logon and idle time and the
// remote client. Usernames are in scope.
package sessions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "sessions", Version: 1}

const (
	Interval    = time.Minute
	MaxSessions = 64
	MaxBytes    = 64 * 1024
	MaxSkipped  = 1 << 16
)

type Collector interface {
	Collect(context.Context) (protocol.Sessions, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Collector.Collect(ctx)
	if e != nil {
		return nil, e
	}
	var skipped int
	v.Sessions, skipped = Bound(v.Sessions)
	v.Skipped = min(v.Skipped+skipped, MaxSkipped)
	if !Valid(v) {
		return nil, features.ErrReport
	}
	b, e := json.Marshal(v)
	if len(b) > MaxBytes {
		return nil, features.ErrReport
	}
	return b, e
}

func text(s string, limit int, required bool) bool {
	if len(s) > limit || !utf8.ValidString(s) || strings.TrimSpace(s) != s || required && s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func SessionValid(v protocol.Session) bool {
	switch v.State {
	case "active", "disconnected", "other":
	default:
		return false
	}
	switch v.Connection {
	case "console", "rdp", "other":
	default:
		return false
	}
	if v.ClientAddress != "" {
		if a, e := netip.ParseAddr(v.ClientAddress); e != nil || a.String() != v.ClientAddress {
			return false
		}
	}
	return text(v.User, 256, true) && text(v.Domain, 256, false) && text(v.Station, 64, false) && text(v.ClientName, 256, false) && v.LogonAt >= 0 && v.IdleSeconds >= -1
}
func Valid(v protocol.Sessions) bool {
	if v.Sessions == nil || len(v.Sessions) > MaxSessions || v.Skipped < 0 || v.Skipped > MaxSkipped {
		return false
	}
	seen := make(map[uint32]bool, len(v.Sessions))
	for _, x := range v.Sessions {
		if !SessionValid(x) || seen[x.ID] {
			return false
		}
		seen[x.ID] = true
	}
	return true
}

// Bound drops sessions with invalid details or a repeated ID, orders the rest
// by session ID and keeps up to MaxSessions; everything left out is counted.
func Bound(list []protocol.Session) ([]protocol.Session, int) {
	valid := make([]protocol.Session, 0, min(len(list), MaxSessions))
	skipped := 0
	seen := map[uint32]bool{}
	for _, x := range list {
		if !SessionValid(x) || seen[x.ID] {
			skipped++
			continue
		}
		seen[x.ID] = true
		valid = append(valid, x)
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].ID < valid[j].ID })
	if len(valid) > MaxSessions {
		skipped += len(valid) - MaxSessions
		valid = valid[:MaxSessions]
	}
	return valid, min(skipped, MaxSkipped)
}

// Normalize is the server's strict decoder: every field is required, unknown
// fields are rejected and the report is re-encoded in canonical order.
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	bad := func() (protocol.FeatureReport, error) { return r, features.ErrReport }
	if r.Capability.Name != Capability.Name || r.Capability.Version < 1 || r.Capability.Version > 999 {
		return bad()
	}
	switch r.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return bad()
	}
	if r.Capability.Version != 1 {
		r.Status, r.Data = "unsupported", nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) != 0 {
			return bad()
		}
		return r, nil
	}
	if len(r.Data) > MaxBytes {
		return bad()
	}
	var input struct {
		Sessions []struct {
			ID            *uint32 `json:"session_id"`
			User          *string `json:"user"`
			Domain        *string `json:"domain"`
			State         *string `json:"state"`
			Connection    *string `json:"connection"`
			Station       *string `json:"station"`
			LogonAt       *int64  `json:"logon_at"`
			IdleSeconds   *int64  `json:"idle_seconds"`
			ClientName    *string `json:"client_name"`
			ClientAddress *string `json:"client_address"`
		} `json:"sessions"`
		Skipped *int `json:"skipped"`
	}
	d := json.NewDecoder(bytes.NewReader(r.Data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || input.Sessions == nil || len(input.Sessions) > MaxSessions {
		return bad()
	}
	v := protocol.Sessions{Sessions: make([]protocol.Session, 0, len(input.Sessions))}
	if input.Skipped != nil {
		v.Skipped = *input.Skipped
	}
	for _, x := range input.Sessions {
		if x.ID == nil || x.User == nil || x.Domain == nil || x.State == nil || x.Connection == nil || x.Station == nil || x.LogonAt == nil || x.IdleSeconds == nil || x.ClientName == nil || x.ClientAddress == nil {
			return bad()
		}
		v.Sessions = append(v.Sessions, protocol.Session{ID: *x.ID, User: *x.User, Domain: *x.Domain, State: *x.State, Connection: *x.Connection, Station: *x.Station, LogonAt: *x.LogonAt, IdleSeconds: *x.IdleSeconds, ClientName: *x.ClientName, ClientAddress: *x.ClientAddress})
	}
	if !Valid(v) {
		return bad()
	}
	sort.Slice(v.Sessions, func(i, j int) bool { return v.Sessions[i].ID < v.Sessions[j].ID })
	r.Data, _ = json.Marshal(v)
	return r, nil
}
