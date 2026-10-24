package storage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

func TestFleetStatusRules(t *testing.T) {
	key, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	latest := &AgentRelease{Release: protocol.SignedAgentRelease{Manifest: protocol.AgentManifest{Sequence: 9, Hash: hash, KeyID: key}}}
	ok := protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: strings.Repeat("c", 64), HighWater: 8, KeyIDs: []string{key}}
	with := func(f func(*protocol.AgentUpgradeSupport)) protocol.AgentUpgradeSupport {
		v := ok
		v.KeyIDs = []string{key}
		f(&v)
		return v
	}
	for _, c := range []struct {
		name    string
		latest  *AgentRelease
		support protocol.AgentUpgradeSupport
		report  string
		online  bool
		job     string
		want    string
	}{
		{"eligible", latest, ok, "ok", true, "", FleetAvailable},
		{"queued job", latest, ok, "ok", true, "queued", FleetUpdating},
		{"same hash", latest, with(func(v *protocol.AgentUpgradeSupport) { v.CurrentHash = hash }), "ok", true, "", FleetUpToDate},
		{"sequence consumed", latest, with(func(v *protocol.AgentUpgradeSupport) { v.HighWater = 9 }), "ok", false, "", FleetUpToDate},
		{"offline", latest, ok, "ok", false, "", FleetOffline},
		{"no release", nil, ok, "ok", true, "", FleetNoRelease},
		{"not reported", latest, ok, "", true, "", FleetUnknown},
		{"feature off", latest, ok, "disabled", true, "", FleetNeedsLocal},
		{"updater missing", latest, with(func(v *protocol.AgentUpgradeSupport) { v.Broker = "missing" }), "ok", true, "", FleetNeedsLocal},
		{"updater off", latest, with(func(v *protocol.AgentUpgradeSupport) { v.Broker = "disabled" }), "ok", true, "", FleetNeedsLocal},
		{"untrusted key", latest, with(func(v *protocol.AgentUpgradeSupport) { v.KeyIDs = []string{strings.Repeat("d", 64)} }), "ok", true, "", FleetNeedsLocal},
	} {
		got, reason := fleetStatus(c.latest, c.support, c.report == "ok", c.report, c.online, c.job)
		if got != c.want || (got == FleetNeedsLocal || got == FleetUnknown) && reason == "" {
			t.Fatal(c.name, got, reason)
		}
	}
}

// Helpers older than this build are flagged for a local reinstall without
// blocking agent updates; old helpers report no revision at all.
func TestFleetFlagsOutdatedHelpers(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	ctx := context.Background()
	reinstall := func() []string {
		t.Helper()
		fleet, e := s.AgentFleet(ctx, now, 120*time.Second)
		if e != nil || len(fleet.Devices) != 1 {
			t.Fatal(e, fleet)
		}
		return fleet.Devices[0].Reinstall
	}
	script := func(admin string, revision int) {
		t.Helper()
		raw, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: admin, RunnerRevision: revision})
		if e := s.RecordScriptSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: raw}, now); e != nil {
			t.Fatal(e)
		}
	}
	update := func(revision int, installer string) {
		t.Helper()
		raw, _ := json.Marshal(protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: strings.Repeat("c", 64), KeyIDs: []string{r.Release.Manifest.KeyID}, UpdaterRevision: revision, Installer: installer})
		if e := s.RecordAgentUpgradeSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: agentupdate.Capability, Status: "ok", Data: raw}, now); e != nil {
			t.Fatal(e)
		}
	}
	script("enabled", 0)
	if got := strings.Join(reinstall(), ","); got != "agent MSI,script runner" {
		t.Fatal("outdated helpers not flagged", got)
	}
	update(agentupdate.Revision, "msi")
	script("missing", 0) // no runner installed: nothing to reinstall
	if got := reinstall(); len(got) != 0 {
		t.Fatal("current or absent helpers flagged", got)
	}
	script("disabled", scripting.RunnerRevision)
	if got := reinstall(); len(got) != 0 {
		t.Fatal("current runner flagged", got)
	}
}

// An MSI release goes only to agents that install MSI packages, an
// executable release only to agents on the earlier separate updater, and
// "already current" compares the installed agent's hash.
func TestUpgradeAllowedMatchesInstaller(t *testing.T) {
	key := strings.Repeat("k", 64)
	exe := AgentRelease{Release: protocol.SignedAgentRelease{Manifest: protocol.AgentManifest{Format: 1, KeyID: key, Sequence: 5, Hash: strings.Repeat("e", 64)}}}
	msi := AgentRelease{Release: protocol.SignedAgentRelease{Manifest: protocol.AgentManifest{Format: 2, Package: "msi", KeyID: key, Sequence: 5, Hash: strings.Repeat("m", 64), AgentHash: strings.Repeat("a", 64)}}}
	legacy := protocol.AgentUpgradeSupport{KeyIDs: []string{key}, HighWater: 4, CurrentHash: strings.Repeat("c", 64)}
	modern := legacy
	modern.Installer = "msi"
	if !upgradeAllowed(legacy, exe) || upgradeAllowed(legacy, msi) || upgradeAllowed(modern, exe) || !upgradeAllowed(modern, msi) {
		t.Fatal("installer and package type must match")
	}
	modern.CurrentHash = msi.Release.Manifest.AgentHash
	if upgradeAllowed(modern, msi) {
		t.Fatal("device already running the packaged agent was offered it again")
	}
	if s, _ := fleetStatus(&msi, modern, true, "ok", true, ""); s != FleetUpToDate {
		t.Fatal("fleet does not compare the installed agent hash", s)
	}
}

func TestFleetExplainsInstallerMismatch(t *testing.T) {
	key := strings.Repeat("k", 64)
	msi := AgentRelease{Release: protocol.SignedAgentRelease{Manifest: protocol.AgentManifest{Format: 2, Package: "msi", KeyID: key, Sequence: 5, Hash: strings.Repeat("m", 64), AgentHash: strings.Repeat("a", 64)}}}
	legacy := protocol.AgentUpgradeSupport{Broker: "enabled", KeyIDs: []string{key}, HighWater: 4, CurrentHash: strings.Repeat("c", 64)}
	if s, why := fleetStatus(&msi, legacy, true, "ok", true, ""); s != FleetNeedsLocal || !strings.Contains(why, "MSI") {
		t.Fatal("agent without MSI self-update offered an MSI release", s, why)
	}
	legacy.Installer = "msi"
	if s, _ := fleetStatus(&msi, legacy, true, "ok", true, ""); s != FleetAvailable {
		t.Fatal("MSI agent not offered the MSI release", s)
	}
}
