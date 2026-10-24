// Package localaccounts reports local Windows user accounts and the members of
// the Administrators and Remote Desktop Users groups.
package localaccounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "local_accounts", Version: 1}

const (
	Interval    = 15 * time.Minute
	MaxAccounts = 512
	MaxMembers  = 256
	MaxBytes    = 512 * 1024
	MaxSkipped  = 1 << 16
)

// Groups are the privileged groups reported, in report order.
var Groups = []string{"administrators", "remote_desktop_users"}

type Collector interface {
	Collect(context.Context) (protocol.LocalAccounts, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Collector.Collect(ctx)
	if e != nil {
		return nil, e
	}
	v = Bound(v)
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

// ValidSID accepts the string form S-1-<authority>-<sub>... with digits only.
func ValidSID(s string) bool {
	if len(s) < 5 || len(s) > 184 || !strings.HasPrefix(s, "S-1-") {
		return false
	}
	for _, part := range strings.Split(s[4:], "-") {
		if part == "" || len(part) > 15 {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
func AccountValid(v protocol.LocalAccount) bool {
	return text(v.Name, 256, true) && text(v.FullName, 256, false) && ValidSID(v.SID) && v.PasswordLastSetAt >= 0 && v.LastLogonAt >= 0
}
func MemberValid(v protocol.GroupMember) bool {
	switch v.Kind {
	case "user", "group", "well_known", "computer", "deleted", "other":
	default:
		return false
	}
	return text(v.Name, 512, false) && ValidSID(v.SID)
}
func Valid(v protocol.LocalAccounts) bool {
	if v.Accounts == nil || len(v.Accounts) > MaxAccounts || v.Skipped < 0 || v.Skipped > MaxSkipped || len(v.Groups) != len(Groups) {
		return false
	}
	seen := map[string]bool{}
	for _, a := range v.Accounts {
		if !AccountValid(a) || seen[a.SID] {
			return false
		}
		seen[a.SID] = true
	}
	for i, g := range v.Groups {
		if g.Key != Groups[i] || !text(g.Name, 256, false) || g.Members == nil || len(g.Members) > MaxMembers || g.Skipped < 0 || g.Skipped > MaxSkipped {
			return false
		}
		members := map[string]bool{}
		for _, m := range g.Members {
			if !MemberValid(m) || members[m.SID] {
				return false
			}
			members[m.SID] = true
		}
	}
	return true
}

// Bound drops invalid or repeated entries, orders accounts by name and members
// by SID, keeps the limits and counts everything left out.
func Bound(v protocol.LocalAccounts) protocol.LocalAccounts {
	out := protocol.LocalAccounts{Accounts: []protocol.LocalAccount{}, Groups: []protocol.LocalGroup{}, Skipped: v.Skipped}
	seen := map[string]bool{}
	for _, a := range v.Accounts {
		if !AccountValid(a) || seen[a.SID] {
			out.Skipped++
			continue
		}
		seen[a.SID] = true
		out.Accounts = append(out.Accounts, a)
	}
	sort.Slice(out.Accounts, func(i, j int) bool {
		return strings.ToLower(out.Accounts[i].Name) < strings.ToLower(out.Accounts[j].Name)
	})
	if len(out.Accounts) > MaxAccounts {
		out.Skipped += len(out.Accounts) - MaxAccounts
		out.Accounts = out.Accounts[:MaxAccounts]
	}
	out.Skipped = min(out.Skipped, MaxSkipped)
	for _, key := range Groups {
		g := protocol.LocalGroup{Key: key, Members: []protocol.GroupMember{}}
		for _, in := range v.Groups {
			if in.Key != key {
				continue
			}
			if text(in.Name, 256, false) {
				g.Name = in.Name
			}
			g.Skipped = in.Skipped
			members := map[string]bool{}
			for _, m := range in.Members {
				if !MemberValid(m) || members[m.SID] {
					g.Skipped++
					continue
				}
				members[m.SID] = true
				g.Members = append(g.Members, m)
			}
		}
		sort.Slice(g.Members, func(i, j int) bool { return g.Members[i].SID < g.Members[j].SID })
		if len(g.Members) > MaxMembers {
			g.Skipped += len(g.Members) - MaxMembers
			g.Members = g.Members[:MaxMembers]
		}
		g.Skipped = min(max(g.Skipped, 0), MaxSkipped)
		out.Groups = append(out.Groups, g)
	}
	return out
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
	type member struct {
		Name *string `json:"name"`
		SID  *string `json:"sid"`
		Kind *string `json:"kind"`
	}
	var input struct {
		Accounts []struct {
			Name                 *string `json:"name"`
			FullName             *string `json:"full_name"`
			SID                  *string `json:"sid"`
			Enabled              *bool   `json:"enabled"`
			LockedOut            *bool   `json:"locked_out"`
			PasswordLastSetAt    *int64  `json:"password_last_set_at"`
			PasswordNeverExpires *bool   `json:"password_never_expires"`
			PasswordExpired      *bool   `json:"password_expired"`
			LastLogonAt          *int64  `json:"last_logon_at"`
		} `json:"accounts"`
		Groups []struct {
			Key     *string  `json:"key"`
			Name    *string  `json:"name"`
			Members []member `json:"members"`
			Skipped *int     `json:"skipped"`
		} `json:"groups"`
		Skipped *int `json:"skipped"`
	}
	d := json.NewDecoder(bytes.NewReader(r.Data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || input.Accounts == nil || input.Groups == nil || len(input.Accounts) > MaxAccounts || len(input.Groups) != len(Groups) {
		return bad()
	}
	v := protocol.LocalAccounts{Accounts: make([]protocol.LocalAccount, 0, len(input.Accounts)), Groups: []protocol.LocalGroup{}}
	if input.Skipped != nil {
		v.Skipped = *input.Skipped
	}
	for _, a := range input.Accounts {
		if a.Name == nil || a.FullName == nil || a.SID == nil || a.Enabled == nil || a.LockedOut == nil || a.PasswordLastSetAt == nil || a.PasswordNeverExpires == nil || a.PasswordExpired == nil || a.LastLogonAt == nil {
			return bad()
		}
		v.Accounts = append(v.Accounts, protocol.LocalAccount{Name: *a.Name, FullName: *a.FullName, SID: *a.SID, Enabled: *a.Enabled, LockedOut: *a.LockedOut, PasswordLastSetAt: *a.PasswordLastSetAt, PasswordNeverExpires: *a.PasswordNeverExpires, PasswordExpired: *a.PasswordExpired, LastLogonAt: *a.LastLogonAt})
	}
	for _, g := range input.Groups {
		if g.Key == nil || g.Name == nil || g.Members == nil || len(g.Members) > MaxMembers {
			return bad()
		}
		out := protocol.LocalGroup{Key: *g.Key, Name: *g.Name, Members: make([]protocol.GroupMember, 0, len(g.Members))}
		if g.Skipped != nil {
			out.Skipped = *g.Skipped
		}
		for _, m := range g.Members {
			if m.Name == nil || m.SID == nil || m.Kind == nil {
				return bad()
			}
			out.Members = append(out.Members, protocol.GroupMember{Name: *m.Name, SID: *m.SID, Kind: *m.Kind})
		}
		v.Groups = append(v.Groups, out)
	}
	if !Valid(v) {
		return bad()
	}
	sort.Slice(v.Accounts, func(i, j int) bool { return strings.ToLower(v.Accounts[i].Name) < strings.ToLower(v.Accounts[j].Name) })
	for _, g := range v.Groups {
		sort.Slice(g.Members, func(i, j int) bool { return g.Members[i].SID < g.Members[j].SID })
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}
