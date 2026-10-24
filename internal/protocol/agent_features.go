package protocol

import "slices"

// AgentFeatures are the agent features an owner can turn off per monitoring
// policy and a local administrator can lock off on a device.
// Everything is on unless a policy or a local lock says otherwise.
// Sorted, so lists built by walking it are sorted too.
var AgentFeatures = []string{"cpu", "desktop", "disk_space", "event_logs", "files", "inventory", "local_accounts", "memory", "processes", "response", "scripts", "services", "sessions", "software", "terminal", "uptime", "windows_updates"}

// LegacyAgentFeatures are the features of the first agents with switchable
// features. They send no feature list and reject a reply that names any
// other feature, so the server only ever sends them these names.
var LegacyAgentFeatures = []string{"cpu", "desktop", "disk_space", "event_logs", "files", "inventory", "memory", "processes", "scripts", "services", "software", "terminal", "uptime", "windows_updates"}

// Understood keeps the names in disabled that an agent understands: the
// features it listed in its heartbeat, or the legacy set when it listed none.
func Understood(disabled, agent []string) []string {
	if len(agent) == 0 {
		agent = LegacyAgentFeatures
	}
	out := []string{}
	for _, f := range disabled {
		if slices.Contains(agent, f) {
			out = append(out, f)
		}
	}
	return out
}

// ValidFeatureNames accepts a sorted list of distinct feature-shaped names,
// including ones this build does not know (a newer agent's).
func ValidFeatureNames(v []string) bool {
	if len(v) > 64 {
		return false
	}
	for i, f := range v {
		if f == "" || len(f) > 32 || i > 0 && v[i-1] >= f {
			return false
		}
		for _, r := range f {
			if !(r >= 'a' && r <= 'z' || r == '_') {
				return false
			}
		}
	}
	return true
}

// ValidFeatureList accepts a sorted list of distinct known feature names.
func ValidFeatureList(v []string) bool {
	if len(v) > len(AgentFeatures) || !slices.IsSorted(v) {
		return false
	}
	for i, f := range v {
		if !slices.Contains(AgentFeatures, f) || i > 0 && v[i-1] == f {
			return false
		}
	}
	return true
}
