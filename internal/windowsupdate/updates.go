// Package windowsupdate owns the bounded Windows Update protocol and OS boundary.
package windowsupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var Capability = protocol.Capability{Name: "windows_updates", Version: 1}

const MaxBytes = 512 * 1024
const MaxCatalog = 100
const MaxSelected = 25

var ErrInvalid = errors.New("invalid update operation")
var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func Decode(b []byte, v any) error {
	if len(b) > MaxBytes {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return ErrInvalid
	}
	return nil
}
func IdentityValid(v protocol.UpdateIdentity) bool {
	return guid.MatchString(v.ID) && v.Revision >= 1 && v.Revision <= 2147483647
}
func Key(v protocol.UpdateIdentity) string { b, _ := json.Marshal(v); return string(b) }
func JobValid(q protocol.UpdateJob) bool {
	if !protocol.ValidID(q.ID) || q.ExpiresAt <= 0 {
		return false
	}
	if (q.WindowStart != 0 || q.WindowEnd != 0) && (q.WindowStart <= 0 || q.WindowEnd <= q.WindowStart || q.WindowEnd-q.WindowStart < 1800 || q.WindowEnd-q.WindowStart > 14400 || q.ExpiresAt > q.WindowEnd) {
		return false
	}
	switch q.Action {
	case "scan", "restart":
		return q.ScanID == "" && len(q.Updates) == 0
	case "install":
		if !protocol.ValidID(q.ScanID) || len(q.Updates) < 1 || len(q.Updates) > MaxSelected {
			return false
		}
		seen := map[string]bool{}
		for _, v := range q.Updates {
			if !IdentityValid(v) || seen[v.ID] {
				return false
			}
			seen[v.ID] = true
		}
		return true
	}
	return false
}
func SupportValid(s protocol.UpdateSupport) bool {
	if s.Broker == "available" {
		return true
	}
	return (s.Broker == "missing" || s.Broker == "denied" || s.Broker == "unsupported") && !s.CanInstall && !s.CanRestart && !s.Windowed
}

// WindowAllows bounds the start of each OS action. Accepted synchronous Windows
// calls are allowed to finish; this is not cancellation or rollback proof.
func WindowAllows(q protocol.UpdateJob, now time.Time) bool {
	if q.WindowStart == 0 && q.WindowEnd == 0 {
		return true
	}
	end := q.WindowEnd
	if q.Action == "restart" {
		end -= 60
	}
	return now.Unix() >= q.WindowStart && now.Unix() < end
}
func text(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// Sanitize makes WUA display text safe to carry: invalid UTF-8 and control
// characters other than tab and line breaks become U+FFFD instead of failing
// the update (and with it the scan). Identifiers are not sanitized into
// validity: a replaced character still fails IdentityValid or the KB check.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
}

// MaxScanned bounds the number of search results examined (and therefore the
// skipped count) for one scan.
const MaxScanned = 10000

// BuildCatalog examines search results in order until MaxCatalog valid,
// distinct updates are collected. describe returns false for a result whose
// metadata cannot be represented; such results and repeated identities are
// skipped and counted. Truncated reports unexamined results.
func BuildCatalog(n int, describe func(int) (protocol.WindowsUpdate, bool)) (catalog []protocol.WindowsUpdate, truncated bool, skipped int) {
	catalog = []protocol.WindowsUpdate{}
	seen := map[string]bool{}
	j := 0
	for ; j < n && j < MaxScanned && len(catalog) < MaxCatalog; j++ {
		u, ok := describe(j)
		if !ok || !ItemValid(u) || seen[u.ID] {
			skipped++
			continue
		}
		seen[u.ID] = true
		catalog = append(catalog, u)
	}
	return catalog, j < n, skipped
}
func ItemValid(v protocol.WindowsUpdate) bool {
	if !IdentityValid(v.UpdateIdentity) || v.Title == "" || !text(v.Title, 512) || !text(v.Description, 1024) || !text(v.Severity, 64) || len(v.KB) > 16 {
		return false
	}
	for _, k := range v.KB {
		if len(k) < 1 || len(k) > 16 || strings.Trim(k, "0123456789") != "" {
			return false
		}
	}
	switch v.Blocked {
	case "", "license_required", "interactive", "upgrade", "unsupported":
		return true
	}
	return false
}
func Terminal(p protocol.UpdateProgress) bool { return p.Phase == "finished" }
func ProgressValid(p protocol.UpdateProgress, q protocol.UpdateJob) bool {
	if p.ID != q.ID || !protocol.ValidID(p.ID) || p.Completed < 0 || p.Total < 0 || p.Completed > p.Total || p.Total > MaxSelected || (!p.RebootKnown && p.RebootRequired) {
		return false
	}
	if p.Phase != "starting" && p.Phase != "searching" && p.Phase != "downloading" && p.Phase != "installing" && p.Phase != "finished" {
		return false
	}
	if q.Action == "scan" && (p.Phase == "downloading" || p.Phase == "installing") {
		return false
	}
	if q.Action == "restart" && p.Phase != "starting" && p.Phase != "finished" {
		return false
	}
	if Terminal(p) {
		switch p.Outcome {
		case "ok", "partial", "failed", "denied", "unsupported", "unavailable", "blocked", "unknown", "restart_scheduled":
		default:
			return false
		}
	} else if p.Outcome != "" {
		return false
	}
	if q.Action != "install" && (p.Total != 0 || p.Completed != 0 || len(p.Items) > 0) {
		return false
	}
	if q.Action == "install" && p.Total != len(q.Updates) {
		return false
	}
	if p.Outcome == "restart_scheduled" && q.Action != "restart" {
		return false
	}
	if len(p.Catalog) > MaxCatalog || len(p.Items) > MaxSelected {
		return false
	}
	if p.Skipped < 0 || p.Skipped > MaxScanned {
		return false
	}
	if (len(p.Catalog) > 0 || p.Truncated || p.Skipped > 0) && (q.Action != "scan" || p.Outcome != "ok" || !Terminal(p)) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range p.Catalog {
		if !ItemValid(v) || seen[v.ID] {
			return false
		}
		seen[v.ID] = true
	}
	for i, v := range p.Items {
		if i >= len(q.Updates) || v.UpdateIdentity != q.Updates[i] {
			return false
		}
		switch v.Outcome {
		case "ok", "failed", "blocked", "unknown":
		default:
			return false
		}
	}
	if len(p.Items) != p.Completed {
		return false
	}
	if q.Action == "install" && p.Outcome == "ok" {
		if p.Completed != p.Total {
			return false
		}
		for _, v := range p.Items {
			if v.Outcome != "ok" {
				return false
			}
		}
	}
	return true
}

type Adapter interface {
	Probe(context.Context) (protocol.UpdateSupport, error)
	Submit(context.Context, protocol.UpdateJob) (protocol.UpdateProgress, error)
	Status(context.Context, string) (protocol.UpdateProgress, error)
}
type Module struct{ Adapter Adapter }

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	s, e := m.Adapter.Probe(ctx)
	if e != nil {
		return nil, e
	}
	if !SupportValid(s) {
		return nil, ErrInvalid
	}
	return json.Marshal(s)
}
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	if r.Capability.Name != Capability.Name || r.Capability.Version < 1 || r.Capability.Version > 999 {
		return r, features.ErrReport
	}
	switch r.Status {
	case "ok", "failed", "disabled", "unsupported":
	default:
		return r, features.ErrReport
	}
	if r.Capability.Version != 1 {
		r.Status = "unsupported"
		r.Data = nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) > 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	var s protocol.UpdateSupport
	if Decode(r.Data, &s) != nil || !SupportValid(s) {
		return r, features.ErrReport
	}
	r.Data, _ = json.Marshal(s)
	return r, nil
}

// IPC is local-only. It never accepts executable names, paths, scripts or WUA criteria.
type IPCRequest struct {
	Op  string              `json:"op"`
	Job *protocol.UpdateJob `json:"job"`
	ID  string              `json:"id"`
}
type IPCReply struct {
	Support  protocol.UpdateSupport   `json:"support"`
	Progress *protocol.UpdateProgress `json:"progress"`
	Error    string                   `json:"error"`
}
