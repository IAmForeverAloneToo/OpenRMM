package protocol

import (
	"net/netip"
	"regexp"
	"slices"
	"time"
)

// Network isolation. The server sends the response actions
// "isolate" and "release"; the agent blocks all network traffic except the
// OpenRMM server, the device's DNS resolvers, DHCP, loopback and the
// policy's allow list, and reports its isolation state in every heartbeat.
// Until isolation has been verified on a disposable machine, agents run it
// in dry-run mode: the rules are worked out and reported, but
// no filter is applied.

// AbilityIsolation is reported by agents that can isolate the device.
const AbilityIsolation = "isolation"

const (
	// MaxIsolationAllow bounds the policy's allow list.
	MaxIsolationAllow = 64
	// MaxReleaseAfter bounds a timed release (optional, off by default).
	MaxReleaseAfter = 7 * 24 * 60 * 60
)

// IsolationSpec is an "isolate" action. Allow is the policy's allow list
// (addresses or networks); CodeHash is the SHA-256 (hex) of the one-time
// release code for the local break-glass command; ReleaseAfter (seconds, 0
// for none) releases the device automatically.
type IsolationSpec struct {
	Allow        []string `json:"allow"`
	CodeHash     string   `json:"code_hash"`
	ReleaseAfter int64    `json:"release_after,omitempty"`
}

// IsolationRule is one kind of traffic isolation lets through. Purpose is
// server, dns, dhcp, loopback or allow; Protocol tcp, udp or any; Port the
// remote port and LocalPort the device's port (0 for any); Direction out or
// both.
type IsolationRule struct {
	Purpose   string `json:"purpose"`
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Remote    string `json:"remote"`
	Port      int    `json:"port,omitempty"`
	LocalPort int    `json:"local_port,omitempty"`
}

// IsolationState is the agent's isolation, reported in heartbeats and as the
// result of isolate and release actions. Mode is enforced (filters applied)
// or dry_run (rules worked out, nothing blocked). Released names the last
// release: server, break_glass or timed, with its time.
type IsolationState struct {
	Isolated   bool            `json:"isolated"`
	Mode       string          `json:"mode,omitempty"`
	Since      string          `json:"since,omitempty"`
	ReleaseAt  string          `json:"release_at,omitempty"`
	Rules      []IsolationRule `json:"rules,omitempty"`
	Released   string          `json:"released,omitempty"`
	ReleasedAt string          `json:"released_at,omitempty"`
	// Job is the isolate action this state belongs to.
	Job   string `json:"job,omitempty"`
	Error string `json:"error,omitempty"`
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidAllowEntry accepts an IP address or network in canonical form.
func ValidAllowEntry(s string) bool {
	if p, e := netip.ParsePrefix(s); e == nil {
		return p.Masked() == p && p.String() == s && p.Bits() > 0
	}
	a, e := netip.ParseAddr(s)
	return e == nil && a.Zone() == "" && !a.Is4In6() && a.String() == s
}

// ValidAllowList checks a policy's isolation allow list.
func ValidAllowList(list []string) bool {
	if len(list) > MaxIsolationAllow {
		return false
	}
	for i, s := range list {
		if !ValidAllowEntry(s) || slices.Contains(list[:i], s) {
			return false
		}
	}
	return true
}

func (s IsolationSpec) Valid() bool {
	return s.Allow != nil && ValidAllowList(s.Allow) && sha256Hex.MatchString(s.CodeHash) && s.ReleaseAfter >= 0 && s.ReleaseAfter <= MaxReleaseAfter
}

func stampValid(s string) bool {
	if s == "" {
		return true
	}
	_, e := time.Parse(time.RFC3339, s)
	return e == nil
}

// Valid checks a reported state.
func (s IsolationState) Valid() bool {
	if s.Mode != "" && s.Mode != "enforced" && s.Mode != "dry_run" || len(s.Rules) > 4*MaxIsolationAllow+64 || len(s.Error) > 512 || s.Job != "" && !ValidID(s.Job) {
		return false
	}
	if s.Isolated && s.Mode == "" || !stampValid(s.Since) || !stampValid(s.ReleaseAt) || !stampValid(s.ReleasedAt) {
		return false
	}
	switch s.Released {
	case "", "server", "break_glass", "timed":
	default:
		return false
	}
	for _, r := range s.Rules {
		if !slices.Contains([]string{"server", "dns", "dhcp", "loopback", "allow"}, r.Purpose) || r.Direction != "out" && r.Direction != "both" ||
			!slices.Contains([]string{"tcp", "udp", "any"}, r.Protocol) || r.Port < 0 || r.Port > 65535 || r.LocalPort < 0 || r.LocalPort > 65535 {
			return false
		}
		if _, e := netip.ParsePrefix(r.Remote); e != nil {
			return false
		}
	}
	return true
}
