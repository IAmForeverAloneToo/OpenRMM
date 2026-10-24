// Package processes owns bounded process snapshots and locally delegated termination.
package processes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/selfprotect"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var Capability = protocol.Capability{Name: "processes", Version: 1}

const Interval = time.Minute
const MaxItems = 4096
const MaxBytes = 1024 * 1024
const Coverage = "visible_processes_accessible_metrics"

type Adapter interface {
	Collect(context.Context) (protocol.Processes, error)
	Execute(context.Context, protocol.ProcessAction) protocol.ProcessResult
}
type Module struct{ Adapter Adapter }

// MaxSkipped bounds the reported count of processes left out of a snapshot.
const MaxSkipped = 1 << 20

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Adapter.Collect(ctx)
	if e != nil {
		return nil, e
	}
	// Adapters normally bound their own lists (with policy priority); this is a
	// no-op for them and keeps any other adapter from failing the whole report.
	var skipped int
	v.Items, skipped = Bound(v.Items, nil)
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
func Name(s string) bool {
	if s == "" || len(s) > 1024 || !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.ContainsAny(s, "/\\") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func Start(s string) bool {
	v, e := strconv.ParseUint(s, 10, 64)
	return e == nil && v > 0 && strconv.FormatUint(v, 10) == s
}
func Manageable(pid uint32, name string) bool {
	if pid <= 4 || !Name(name) {
		return false
	}
	if selfprotect.Executable(name) {
		return false
	}
	return !ProtectedName(name)
}

// ProtectedName reports the names of Windows processes that must not be
// ended. The RMM process view refuses them anywhere; a case kill refuses
// them only when they run from the system folder,
// so malware borrowing such a name elsewhere can be ended.
func ProtectedName(name string) bool {
	switch strings.ToLower(name) {
	case "system", "registry", "secure system", "memory compression", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe":
		return true
	}
	return false
}

// ItemValid checks one process independently of the rest of the snapshot.
func ItemValid(x protocol.Process) bool {
	return Name(x.Name) && (x.Start == "" || Start(x.Start)) && (x.CPU == nil || *x.CPU <= 10000 && x.Start != "") && (x.Memory == nil || *x.Memory <= 1<<60) && (!x.CanTerminate || Manageable(x.PID, x.Name) && Start(x.Start))
}
func Valid(v protocol.Processes) bool {
	if v.Coverage != Coverage || v.Items == nil || len(v.Items) > MaxItems || v.Skipped < 0 || v.Skipped > MaxSkipped {
		return false
	}
	seen := map[uint32]bool{}
	for _, x := range v.Items {
		if seen[x.PID] || !ItemValid(x) {
			return false
		}
		seen[x.PID] = true
	}
	return true
}

// itemBudget is the largest serialized size of a process other than its name:
// every numeric field at its maximum width plus separators.
var itemBudget = func() int {
	cpu, memory := uint32(10000), uint64(1<<64-1)
	b, _ := json.Marshal(protocol.Process{PID: 1<<32 - 1, Start: "18446744073709551615", CPU: &cpu, Memory: &memory})
	return len(b) + 1
}()

// Bound turns a raw process listing into a snapshot that always fits the
// report limits instead of failing as a whole. Items with invalid metadata and
// repeated PIDs are dropped. The remaining order is: processes for which
// priority returns true (the locally delegated termination targets) first, then
// ascending PID. Items are kept in that order until MaxItems or the 1 MiB
// report budget is reached; everything else is counted as skipped. Windows
// assigns PIDs, so a standard user flooding the machine with processes cannot
// displace delegated targets or choose which existing process is dropped, and
// early boot-time system processes (low PIDs) stay visible. The result is
// sorted by PID.
func Bound(items []protocol.Process, priority func(protocol.Process) bool) ([]protocol.Process, int) {
	type candidate struct {
		protocol.Process
		first bool
	}
	candidates := make([]candidate, 0, min(len(items), MaxItems))
	skipped := 0
	for _, x := range items {
		if !ItemValid(x) {
			skipped++
			continue
		}
		candidates = append(candidates, candidate{x, priority != nil && priority(x)})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].first != candidates[j].first {
			return candidates[i].first
		}
		return candidates[i].PID < candidates[j].PID
	})
	budget := MaxBytes - len(`{"coverage":"`+Coverage+`","items":[],"skipped":1048576}`)
	kept := make([]protocol.Process, 0, min(len(candidates), MaxItems))
	seen := make(map[uint32]bool, len(candidates))
	for _, x := range candidates {
		if seen[x.PID] {
			skipped++
			continue
		}
		seen[x.PID] = true
		name, _ := json.Marshal(x.Name)
		if len(kept) >= MaxItems || budget < itemBudget+len(name) {
			skipped++
			continue
		}
		budget -= itemBudget + len(name)
		kept = append(kept, x.Process)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].PID < kept[j].PID })
	return kept, min(skipped, MaxSkipped)
}
func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return features.ErrReport
	}
	return nil
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
		if len(r.Data) != 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	if len(r.Data) > MaxBytes {
		return r, features.ErrReport
	}
	// Skipped is optional: agents before the skip count omit it (zero).
	var shape struct {
		Coverage *string         `json:"coverage"`
		Items    json.RawMessage `json:"items"`
		Skipped  *int            `json:"skipped"`
	}
	if Decode(r.Data, &shape) != nil || shape.Coverage == nil {
		return r, features.ErrReport
	}
	d := json.NewDecoder(bytes.NewReader(shape.Items))
	d.DisallowUnknownFields()
	tok, e := d.Token()
	if e != nil || tok != json.Delim('[') {
		return r, features.ErrReport
	}
	v := protocol.Processes{Coverage: *shape.Coverage, Items: []protocol.Process{}}
	if shape.Skipped != nil {
		v.Skipped = *shape.Skipped
	}
	for d.More() {
		if len(v.Items) >= MaxItems {
			return r, features.ErrReport
		}
		var x struct {
			PID    *uint32         `json:"pid"`
			Start  *string         `json:"start"`
			Name   *string         `json:"name"`
			CPU    json.RawMessage `json:"cpu_basis_points"`
			Memory json.RawMessage `json:"working_set_bytes"`
			Can    *bool           `json:"can_terminate"`
		}
		if d.Decode(&x) != nil || x.PID == nil || x.Start == nil || x.Name == nil || x.Can == nil || len(x.CPU) == 0 || len(x.Memory) == 0 {
			return r, features.ErrReport
		}
		p := protocol.Process{PID: *x.PID, Start: *x.Start, Name: *x.Name, CanTerminate: *x.Can}
		if json.Unmarshal(x.CPU, &p.CPU) != nil || json.Unmarshal(x.Memory, &p.Memory) != nil {
			return r, features.ErrReport
		}
		v.Items = append(v.Items, p)
	}
	if _, e = d.Token(); e != nil || !errors.Is(d.Decode(new(any)), io.EOF) || !Valid(v) {
		return r, features.ErrReport
	}
	sort.Slice(v.Items, func(i, j int) bool { return v.Items[i].PID < v.Items[j].PID })
	r.Data, _ = json.Marshal(v)
	return r, nil
}

func ResultValid(r protocol.ProcessResult) bool {
	if !protocol.ValidID(r.ID) {
		return false
	}
	switch r.Outcome {
	case "succeeded", "denied", "not_found", "identity_changed", "timed_out", "failed", "interrupted":
		return true
	}
	return false
}

// CPU is normalized to total machine capacity. Monotonic elapsed time is local;
// creation time binds the two samples to one instance. Missing is never zero.
func CPU(before, after uint64, elapsed time.Duration, processors uint32) *uint32 {
	if after < before || elapsed <= 0 || processors == 0 {
		return nil
	}
	n := float64(after-before) * 100 / float64(elapsed.Nanoseconds()) * 10000 / float64(processors)
	if n < 0 || n > 10100 {
		return nil
	}
	v := uint32(min(n, 10000))
	return &v
}
