package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Features are on unless the device's monitoring policy turns
// them off (sent with every heartbeat reply) or a local administrator locks
// them off (command-line switch or HKLM\SOFTWARE\Policies\OpenRMM\Agent).
// A local lock always wins: a policy cannot turn a locked feature back on.

const featureSettingsFile = "feature-settings.json"

func featureSwitches(c *config.Agent) map[string]*bool {
	return map[string]*bool{
		"inventory": &c.Inventory, "disk_space": &c.DiskSpace, "memory": &c.Memory, "cpu": &c.CPU, "uptime": &c.Uptime,
		"services": &c.Services, "event_logs": &c.EventLogs, "windows_updates": &c.WindowsUpdates, "software": &c.Software,
		"sessions": &c.Sessions, "local_accounts": &c.LocalAccounts, "response": &c.Response, "processes": &c.Processes, "scripts": &c.Scripts, "desktop": &c.Desktop, "terminal": &c.Terminal, "files": &c.Files,
	}
}

// localLocks lists, sorted, the features turned off on this device itself.
// The desktop pipe exists only in the installed service, so a console agent
// does not report it as locked.
func localLocks(c config.Agent) []string {
	policy := policyLocks()
	switches := featureSwitches(&c)
	out := []string{}
	for _, f := range protocol.AgentFeatures {
		if f == "desktop" && !c.Service {
			continue
		}
		if !*switches[f] || policy[f] {
			out = append(out, f)
		}
	}
	return out
}

// withFeatures turns off every feature that is locked locally or disabled by
// the server; it never turns a feature on.
func withFeatures(c config.Agent, off ...[]string) config.Agent {
	switches := featureSwitches(&c)
	for _, list := range off {
		for _, f := range list {
			if p, ok := switches[f]; ok {
				*p = false
			}
		}
	}
	return c
}

// loadDisabled returns the last policy settings received, so a restart never
// briefly runs a feature the server turned off. Missing or unreadable means
// none (the next heartbeat reply corrects it).
func loadDisabled(state string) []string {
	raw, e := os.ReadFile(filepath.Join(state, featureSettingsFile))
	var v struct {
		Disabled []string `json:"disabled"`
	}
	if e != nil || len(raw) > 4096 || json.Unmarshal(raw, &v) != nil || !protocol.ValidFeatureList(v.Disabled) {
		return []string{}
	}
	if v.Disabled == nil {
		return []string{}
	}
	return v.Disabled
}
func saveDisabled(state string, disabled []string) error {
	raw, _ := json.Marshal(struct {
		Disabled []string `json:"disabled"`
	}{disabled})
	path := filepath.Join(state, featureSettingsFile)
	if e := os.WriteFile(path+".tmp", raw, 0600); e != nil {
		return e
	}
	return os.Rename(path+".tmp", path)
}

// featuresChanged reports whether a heartbeat reply asks for other settings.
func featuresChanged(current, received []string) bool {
	if received == nil {
		received = []string{}
	}
	return protocol.ValidFeatureList(received) && !slices.Equal(current, received)
}
