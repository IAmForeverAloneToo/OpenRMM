package protocol

import "slices"

// DeviceStatusHeader accompanies a 403 from the device listener when the
// presented device identity has been revoked (value "revoked"). Any other
// authentication failure omits it, so agents can tell a deliberate revocation
// from a transient or unexpected rejection (for example from a proxy).
const DeviceStatusHeader = "X-OpenRMM-Device-Status"

type Heartbeat struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	AgentVersion string `json:"agent_version"`
	// Locked lists features a local administrator turned off on this device;
	// a server policy cannot turn them back on.
	Locked []string `json:"locked,omitempty"`
	// Features lists the switchable features this agent understands, so
	// replies name only those. Older agents omit it.
	Features []string `json:"features,omitempty"`
	// Abilities lists what this agent can do beyond its features (for
	// example AbilityTriage), so the server sends only work it can run.
	// Older agents omit it.
	Abilities []string `json:"abilities,omitempty"`
	// Isolation is the device's network isolation; older agents
	// omit it.
	Isolation *IsolationState `json:"isolation,omitempty"`
}
type HeartbeatReceipt struct {
	DeviceID   string `json:"device_id"`
	ReceivedAt int64  `json:"received_at"`
	// Disabled lists the features this device's monitoring policy turns off
	// (heartbeat replies only). Empty means everything on.
	Disabled []string `json:"disabled,omitempty"`
}

func (h Heartbeat) Valid() bool {
	if !ValidMetadata(h.Hostname, h.OS, h.Architecture) || len(h.AgentVersion) == 0 || len(h.AgentVersion) > 64 || !ValidFeatureList(h.Locked) || !ValidFeatureNames(h.Features) || !ValidAbilities(h.Abilities) || h.Isolation != nil && !h.Isolation.Valid() {
		return false
	}
	for _, character := range h.AgentVersion {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '-' || character == '+' || character == '_') {
			return false
		}
	}
	return true
}

// ValidAbilities accepts up to 32 sorted, distinct names of lowercase letters,
// digits and underscores (unknown ones are kept: a newer agent may report
// abilities this server does not use).
func ValidAbilities(v []string) bool {
	if len(v) > 32 || !slices.IsSorted(v) {
		return false
	}
	for i, a := range v {
		if a == "" || len(a) > 32 || i > 0 && v[i-1] == a {
			return false
		}
		for _, r := range a {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
				return false
			}
		}
	}
	return true
}
