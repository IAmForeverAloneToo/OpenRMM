// Package winservices owns Windows service snapshots and narrowly scoped actions.
package winservices

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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var Capability = protocol.Capability{Name: "services", Version: 1}

const Interval = time.Minute
const MaxItems = 2048
const MaxBytes = 2 * 1024 * 1024

type Adapter interface {
	Collect(context.Context) (protocol.Services, error)
	Execute(context.Context, protocol.ServiceAction) protocol.ServiceResult
}
type Module struct{ Adapter Adapter }

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, err := m.Adapter.Collect(ctx)
	if err != nil {
		return nil, err
	}
	if !Valid(v) {
		return nil, errors.New("invalid service snapshot")
	}
	data, err := json.Marshal(v)
	if err != nil || len(data) > MaxBytes {
		return nil, errors.New("service snapshot exceeds the payload limit")
	}
	return data, nil
}
func Text(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func Name(s string) bool { return Text(s, 1024) && !strings.ContainsAny(s, "/\\") }

// Manageable refuses every OpenRMM service (see internal/selfprotect).
func Manageable(s string) bool { return Name(s) && !selfprotect.Service(s) }
func Action(s string) bool     { return s == "start" || s == "stop" || s == "restart" }
func State(s string) bool {
	switch s {
	case "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused":
		return true
	}
	return false
}
func Valid(v protocol.Services) bool {
	if v.Visibility != "queryable_services_only" || v.Items == nil || len(v.Items) > MaxItems {
		return false
	}
	seen := map[string]bool{}
	for _, s := range v.Items {
		key := strings.ToLower(s.Name)
		if !Name(s.Name) || !Text(s.DisplayName, 1024) || !State(s.State) || seen[key] || (!Manageable(s.Name) && (s.CanStart || s.CanStop)) {
			return false
		}
		seen[key] = true
	}
	return true
}
func Decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
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
	var v protocol.Services
	// Required boolean fields need explicit presence; false must not mask omission.
	var shape struct {
		Items []struct {
			Name    *string `json:"name"`
			Display *string `json:"display_name"`
			State   *string `json:"state"`
			Start   *bool   `json:"can_start"`
			Stop    *bool   `json:"can_stop"`
		} `json:"items"`
		Visibility *string `json:"visibility"`
	}
	if len(r.Data) > MaxBytes || Decode(r.Data, &shape) != nil || shape.Visibility == nil || shape.Items == nil {
		return r, features.ErrReport
	}
	for _, s := range shape.Items {
		if s.Name == nil || s.Display == nil || s.State == nil || s.Start == nil || s.Stop == nil {
			return r, features.ErrReport
		}
	}
	if Decode(r.Data, &v) != nil || !Valid(v) {
		return r, features.ErrReport
	}
	sort.Slice(v.Items, func(i, j int) bool { return strings.ToLower(v.Items[i].Name) < strings.ToLower(v.Items[j].Name) })
	r.Data, _ = json.Marshal(v)
	return r, nil
}
func ResultValid(r protocol.ServiceResult) bool {
	if !protocol.ValidID(r.ID) || r.State != "unknown" && !State(r.State) {
		return false
	}
	switch r.Outcome {
	case "succeeded", "denied", "not_found", "pending", "dependent_services", "timed_out", "failed", "interrupted":
		return true
	}
	return false
}
