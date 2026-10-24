package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestFeatureLocksAndPolicySettings(t *testing.T) {
	if !slices.IsSorted(protocol.AgentFeatures) {
		t.Fatal("protocol.AgentFeatures must stay sorted; feature lists are built by walking it")
	}
	c, e := config.LoadAgent([]string{"-terminal=false", "-files=false"}, func(string) string { return "" })
	if e != nil {
		t.Fatal(e)
	}
	// A console agent never offers the desktop pipe, so it is not reported.
	if got := localLocks(c); !slices.Equal(got, []string{"files", "terminal"}) {
		t.Fatal("local locks", got)
	}
	applied := withFeatures(c, localLocks(c), []string{"scripts", "terminal"})
	if applied.Scripts || applied.Terminal || applied.Files || !applied.Processes || !applied.Inventory {
		t.Fatal("policy and locks not applied, or unrelated features changed", applied)
	}
	// A policy can only turn features off, never back on.
	if again := withFeatures(applied); again.Terminal {
		t.Fatal("feature turned back on")
	}
	if !featuresChanged([]string{"terminal"}, nil) || featuresChanged([]string{}, nil) || featuresChanged([]string{"files"}, []string{"files"}) {
		t.Fatal("change detection")
	}
	if featuresChanged([]string{}, []string{"terminal", "files"}) || featuresChanged([]string{}, []string{"nonsense"}) {
		t.Fatal("invalid (unsorted or unknown) settings must be ignored")
	}
}

func TestFeatureSettingsPersist(t *testing.T) {
	state := t.TempDir()
	if got := loadDisabled(state); len(got) != 0 {
		t.Fatal("missing file must mean everything on", got)
	}
	if e := saveDisabled(state, []string{"desktop", "terminal"}); e != nil {
		t.Fatal(e)
	}
	if got := loadDisabled(state); !slices.Equal(got, []string{"desktop", "terminal"}) {
		t.Fatal("saved settings", got)
	}
	if e := os.WriteFile(filepath.Join(state, featureSettingsFile), []byte(`{"disabled":["zzz"]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if got := loadDisabled(state); len(got) != 0 {
		t.Fatal("corrupt settings must fall back to everything on", got)
	}
}
