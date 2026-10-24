// Package securitystatus reports a device's disk encryption and antivirus
// state: BitLocker volumes, Microsoft Defender and the antivirus
// products Windows Security Center knows. It belongs to the Inventory
// feature (inventory plus fleet columns).
package securitystatus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var Capability = protocol.Capability{Name: "security_status", Version: 1}

const (
	Interval   = time.Hour
	Timeout    = 90 * time.Second
	MaxBytes   = 64 * 1024
	MaxVolumes = 64
	MaxAV      = 16
)

type Collector interface {
	Collect(context.Context) (protocol.SecurityStatus, error)
}
type Module struct{ Collector Collector }

func (m Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	v, e := m.Collector.Collect(ctx)
	if e != nil {
		return nil, e
	}
	if !Valid(v) {
		return nil, features.ErrReport
	}
	b, e := json.Marshal(v)
	if len(b) > MaxBytes {
		return nil, features.ErrReport
	}
	return b, e
}

func text(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func stamp(s string) bool {
	if s == "" {
		return true
	}
	_, e := time.Parse(time.RFC3339, s)
	return e == nil
}

// Valid checks a report.
func Valid(v protocol.SecurityStatus) bool {
	states := []string{"available", "not_installed", "unavailable", "absent"}
	if !slices.Contains(states, v.BitLockerState) || !slices.Contains(states, v.DefenderState) || v.BitLocker == nil || v.Antivirus == nil || len(v.BitLocker) > MaxVolumes || len(v.Antivirus) > MaxAV {
		return false
	}
	if (v.DefenderState == "available") != (v.Defender != nil) {
		return false
	}
	for _, b := range v.BitLocker {
		if !text(b.Drive, 64) || !slices.Contains([]string{"os", "fixed", "removable"}, b.Type) || !slices.Contains([]string{"on", "off", "unknown"}, b.Protection) ||
			!slices.Contains([]string{"fully_decrypted", "fully_encrypted", "encrypting", "decrypting", "paused", "unknown"}, b.Conversion) || b.Percent < 0 || b.Percent > 100 || !text(b.Method, 64) {
			return false
		}
	}
	if d := v.Defender; d != nil {
		if !text(d.Mode, 32) || !text(d.ProductVersion, 64) || !text(d.SignatureVersion, 64) || !stamp(d.SignatureUpdated) || !stamp(d.QuickScanCompleted) || !stamp(d.FullScanCompleted) {
			return false
		}
	}
	for _, a := range v.Antivirus {
		if a.Name == "" || !text(a.Name, 256) {
			return false
		}
	}
	return true
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return features.ErrReport
	}
	return nil
}

// Normalize checks a report received from an agent.
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
		r.Status, r.Data = "unsupported", nil
		return r, nil
	}
	if r.Status != "ok" {
		if len(r.Data) > 0 {
			return r, features.ErrReport
		}
		return r, nil
	}
	var v protocol.SecurityStatus
	if decode(r.Data, &v) != nil || !Valid(v) {
		return r, features.ErrReport
	}
	r.Data, _ = json.Marshal(v)
	return r, nil
}

// otherAV is an enabled antivirus product other than Microsoft Defender.
func otherAV(list []protocol.AntivirusProduct) bool {
	for _, a := range list {
		if a.Enabled && !strings.Contains(strings.ToLower(a.Name), "defender") {
			return true
		}
	}
	return false
}

// Summary is what the device list shows: BitLocker on the operating system
// volume (on, suspended, encrypting, off, not_installed, unknown) and Defender
// (on, real_time_off, off, passive, other_av, absent, unknown). other_av is
// Defender turned off while Security Center lists another enabled antivirus. Suspended is a fully
// encrypted volume whose protection is off: its key is stored in the clear.
func Summary(v protocol.SecurityStatus) (bitlocker, defender string) {
	bitlocker = "unknown"
	switch v.BitLockerState {
	case "not_installed":
		bitlocker = "not_installed"
	case "available":
		for _, b := range v.BitLocker {
			if b.Type != "os" {
				continue
			}
			switch {
			case b.Protection == "on" && b.Conversion == "fully_encrypted":
				bitlocker = "on"
			case b.Conversion == "fully_encrypted":
				bitlocker = "suspended"
			case b.Conversion == "encrypting" || b.Conversion == "paused":
				bitlocker = "encrypting"
			default:
				bitlocker = "off"
			}
		}
	}
	defender = "unknown"
	switch {
	case v.DefenderState == "absent":
		defender = "absent"
	case v.Defender != nil:
		d := v.Defender
		switch {
		case strings.Contains(d.Mode, "passive"):
			defender = "passive"
		case (!d.ServiceEnabled || !d.AntivirusEnabled || d.Mode == "not_running") && otherAV(v.Antivirus):
			defender = "other_av"
		case !d.ServiceEnabled || !d.AntivirusEnabled:
			defender = "off"
		case !d.RealTime:
			defender = "real_time_off"
		default:
			defender = "on"
		}
	}
	return bitlocker, defender
}
