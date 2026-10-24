// Package patching defines a bounded Windows patch-policy adapter. Scheduling
// and execution remain separate from reviewed definitions and target snapshots.
package patching

import (
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("patch policy or targets changed/unavailable; reload and review again")

const MaxTargets = 25
const MaxKB = 64

type Definition struct {
	Name       string   `json:"name"`
	Ring       string   `json:"ring"`
	Devices    []string `json:"devices"`
	Weekday    int      `json:"weekday"`
	Minute     int      `json:"minute_utc"`
	Duration   int      `json:"duration_minutes"`
	Install    bool     `json:"install"`
	KB         []string `json:"approved_kb"`
	Restart    bool     `json:"restart_after_deferral"`
	DeferHours int      `json:"defer_hours"`
}

func Text(s string, n int) bool {
	if len(s) == 0 || len(s) > n || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

var kb = regexp.MustCompile(`^[1-9][0-9]{3,15}$`)

func Valid(d Definition) bool {
	if !Text(d.Name, 100) || !Text(d.Ring, 40) || len(d.Devices) == 0 || len(d.Devices) > MaxTargets || d.Weekday < 0 || d.Weekday > 6 || d.Minute < 0 || d.Minute >= 1440 || d.Duration < 30 || d.Duration > 240 || len(d.KB) > MaxKB || d.Install && len(d.KB) == 0 || !d.Install && len(d.KB) > 0 || d.DeferHours < 1 || d.DeferHours > 168 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range d.Devices {
		if !protocol.ValidID(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, id := range d.KB {
		if !kb.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func Normalize(d Definition) Definition {
	d.Devices = append([]string(nil), d.Devices...)
	d.KB = append([]string(nil), d.KB...)
	sort.Strings(d.Devices)
	sort.Strings(d.KB)
	return d
}

// Next always returns a future window. UTC avoids DST ambiguity in this first
// recurrence adapter; no local timezone or catch-up interpretation is hidden.
func Next(d Definition, after time.Time) time.Time {
	t := after.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	next := day.AddDate(0, 0, (d.Weekday-int(day.Weekday())+7)%7).Add(time.Duration(d.Minute) * time.Minute)
	if !next.After(after) {
		next = next.AddDate(0, 0, 7)
	}
	return next
}

// Selection requires a complete successful scan. Every advertised KB for an
// eligible update must be explicitly approved; unknown metadata is not approval.
func Selection(d Definition, p protocol.UpdateProgress) ([]protocol.UpdateIdentity, error) {
	// Skipped updates are unidentified, so an approved update could hide among
	// them; selection and verification treat such a scan as incomplete.
	if p.Phase != "finished" || p.Outcome != "ok" || p.Truncated || p.Skipped > 0 || !p.RebootKnown {
		return nil, ErrInvalid
	}
	approved := map[string]bool{}
	for _, id := range d.KB {
		approved[id] = true
	}
	result := []protocol.UpdateIdentity{}
	for _, u := range p.Catalog {
		if len(u.KB) == 0 {
			continue
		}
		all := true
		any := false
		for _, id := range u.KB {
			if approved[id] {
				any = true
			} else {
				all = false
			}
		}
		if any && !all {
			return nil, ErrInvalid
		}
		if all {
			if u.Blocked != "" {
				return nil, ErrInvalid
			}
			result = append(result, u.UpdateIdentity)
		}
	}
	if len(result) > 25 {
		return nil, ErrInvalid
	}
	return result, nil
}
