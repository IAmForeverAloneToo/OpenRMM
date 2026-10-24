// Package software implements read-only software inventory through an OS boundary.
package software

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Version 2 adds per-user registrations from loaded user hives.
var Capability = protocol.Capability{Name: "software", Version: 2}

// CapabilityV1 is reported by older agents (machine-wide only).
var CapabilityV1 = protocol.Capability{Name: "software", Version: 1}

const (
	Coverage = "machine_uninstall_registry_32_64"
	// CoverageUsers adds the registrations of signed-in users (version 2).
	CoverageUsers = "machine_uninstall_registry_32_64_loaded_users"
	MaxUsers      = 64
	// usersReserve is the report budget kept for the users list: at most
	// MaxUsers entries of a 184-byte SID and a 256-byte name, which JSON
	// escaping can make up to six times longer.
	usersReserve = 128 * 1024
	Interval     = 15 * time.Minute
	// Timeout bounds a collection, which resolves signed-in users' account
	// names (a domain lookup can be slow).
	Timeout    = 30 * time.Second
	MaxEntries = 2048
	MaxBytes   = 1024 * 1024
	// MaxSkipped bounds the reported count of registrations left out.
	MaxSkipped = 1 << 20
)

type Collector interface {
	Collect(context.Context) (protocol.Software, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Collector.Collect(ctx)
	if e != nil {
		return nil, e
	}
	perUser := func() int {
		n := 0
		for _, x := range v.Entries {
			if x.View == "user" {
				n++
			}
		}
		return n
	}
	before := perUser()
	var skipped int
	v.Entries, skipped = Bound(v.Entries)
	userDropped := min(before-perUser(), skipped)
	v.Skipped = min(v.Skipped+skipped-userDropped, MaxSkipped)
	v.UserSkipped = min(v.UserSkipped+userDropped, MaxSkipped)
	if !Valid(v) {
		return nil, features.ErrReport
	}
	b, e := json.Marshal(v)
	if len(b) > MaxBytes {
		return nil, features.ErrReport
	}
	return b, e
}
func Text(s string, limit int, required bool) bool {
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

var userSID = regexp.MustCompile(`^S-1-(5-21|12-1)(-[0-9]{1,10}){1,15}$`)

// UserSIDValid is the SID of a user hive that may hold per-user software:
// local or domain (S-1-5-21-...) and Microsoft Entra ID (S-1-12-1-...) users.
func UserSIDValid(s string) bool { return len(s) <= 184 && userSID.MatchString(s) }

func EntryValid(v protocol.SoftwareEntry) bool {
	if len(v.ID) != 64 {
		return false
	}
	b, e := hex.DecodeString(v.ID)
	if e != nil || len(b) != 32 || strings.ToLower(v.ID) != v.ID || !Text(v.Name, 512, true) || !Text(v.Version, 256, false) || !Text(v.Publisher, 512, false) {
		return false
	}
	switch v.View {
	case "32", "64":
		return v.User == "" && v.UserSID == ""
	case "user":
		return Text(v.User, 256, true) && UserSIDValid(v.UserSID)
	}
	return false
}
func Valid(v protocol.Software) bool {
	if v.Coverage != Coverage && v.Coverage != CoverageUsers || v.Entries == nil || len(v.Entries) > MaxEntries || v.Skipped < 0 || v.Skipped > MaxSkipped || len(v.Users) > MaxUsers {
		return false
	}
	if v.UserSkipped < 0 || v.UserSkipped > MaxSkipped || v.Coverage == Coverage && (len(v.Users) > 0 || v.UserSkipped > 0) {
		return false
	}
	users := make(map[string]bool, len(v.Users))
	for _, u := range v.Users {
		if !UserSIDValid(u.SID) || !Text(u.Name, 256, true) || users[u.SID] {
			return false
		}
		users[u.SID] = true
	}
	seen := make(map[string]bool, len(v.Entries))
	for _, x := range v.Entries {
		if !EntryValid(x) || seen[x.ID] || x.View == "user" && !users[x.UserSID] {
			return false
		}
		seen[x.ID] = true
	}
	return true
}

// Bound turns collected registrations into an inventory that always fits the
// report limits instead of failing as a whole. Entries with invalid metadata and
// repeated IDs are dropped. The rest are ordered by ID (a digest of registry
// view and key name, so the order is stable and not chosen by display text) and
// kept until MaxEntries or the 1 MiB report budget is reached. Everything left
// out is counted as skipped.
func Bound(entries []protocol.SoftwareEntry) ([]protocol.SoftwareEntry, int) {
	valid := make([]protocol.SoftwareEntry, 0, min(len(entries), MaxEntries))
	skipped := 0
	for _, x := range entries {
		if EntryValid(x) {
			valid = append(valid, x)
		} else {
			skipped++
		}
	}
	sort.SliceStable(valid, func(i, j int) bool { return valid[i].ID < valid[j].ID })
	budget := MaxBytes - len(`{"coverage":"`+CoverageUsers+`","entries":[],"skipped":1048576,"users":[]}`) - usersReserve
	kept := make([]protocol.SoftwareEntry, 0, min(len(valid), MaxEntries))
	for i, x := range valid {
		if i > 0 && valid[i-1].ID == x.ID {
			skipped++
			continue
		}
		b, _ := json.Marshal(x)
		if len(kept) >= MaxEntries || budget < len(b)+1 {
			skipped++
			continue
		}
		budget -= len(b) + 1
		kept = append(kept, x)
	}
	return kept, min(skipped, MaxSkipped)
}
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
	if r.Capability.Version > 2 {
		r.Status, r.Data = "unsupported", nil
		return r, nil
	}
	coverage := Coverage
	if r.Capability.Version == 2 {
		coverage = CoverageUsers
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
	// Pointers distinguish missing fields/null from intentionally empty metadata.
	// Skipped is optional: agents before the skip count omit it (zero).
	var input struct {
		Coverage *string                 `json:"coverage"`
		Entries  json.RawMessage         `json:"entries"`
		Skipped  *int                    `json:"skipped"`
		Users    []protocol.SoftwareUser `json:"users"`
		UserSkip int                     `json:"user_skipped"`
	}
	d := json.NewDecoder(bytes.NewReader(r.Data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || input.Coverage == nil || *input.Coverage != coverage || len(input.Users) > MaxUsers {
		return bad()
	}
	// Stream the array so an attacker cannot allocate an unbounded number of
	// entry structs before the count limit is checked.
	array := json.NewDecoder(bytes.NewReader(input.Entries))
	array.DisallowUnknownFields()
	if token, e := array.Token(); e != nil || token != json.Delim('[') {
		return bad()
	}
	v := protocol.Software{Coverage: *input.Coverage, Entries: []protocol.SoftwareEntry{}, Users: input.Users, UserSkipped: input.UserSkip}
	if input.Skipped != nil {
		v.Skipped = *input.Skipped
	}
	for array.More() {
		if len(v.Entries) >= MaxEntries {
			return bad()
		}
		var x struct {
			ID        *string `json:"id"`
			View      *string `json:"registry_view"`
			Name      *string `json:"name"`
			Version   *string `json:"version"`
			Publisher *string `json:"publisher"`
			User      string  `json:"user"`
			UserSID   string  `json:"user_sid"`
		}
		if array.Decode(&x) != nil {
			return bad()
		}
		if x.ID == nil || x.View == nil || x.Name == nil || x.Version == nil || x.Publisher == nil {
			return bad()
		}
		v.Entries = append(v.Entries, protocol.SoftwareEntry{ID: *x.ID, View: *x.View, Name: *x.Name, Version: *x.Version, Publisher: *x.Publisher, User: x.User, UserSID: x.UserSID})
	}
	if token, e := array.Token(); e != nil || token != json.Delim(']') {
		return bad()
	}
	if !errors.Is(array.Decode(new(any)), io.EOF) {
		return bad()
	}
	if !Valid(v) {
		return bad()
	}
	sort.Slice(v.Entries, func(i, j int) bool { return v.Entries[i].ID < v.Entries[j].ID })
	sort.Slice(v.Users, func(i, j int) bool { return v.Users[i].SID < v.Users[j].SID })
	r.Data, _ = json.Marshal(v)
	if len(r.Data) > MaxBytes {
		return bad()
	}
	return r, nil
}
