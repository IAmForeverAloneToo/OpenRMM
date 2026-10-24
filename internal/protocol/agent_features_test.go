package protocol

import (
	"slices"
	"testing"
)

// A legacy agent rejects a reply naming a feature it does not
// know (and with it every other switch), so replies carry only names the
// agent understands.
func TestUnderstoodKeepsOldAgentsSwitches(t *testing.T) {
	disabled := []string{"scripts", "sessions", "terminal"}
	if got := Understood(disabled, nil); !slices.Equal(got, []string{"scripts", "terminal"}) || !ValidFeatureList(got) {
		t.Fatal("legacy agent", got)
	}
	if got := Understood(disabled, AgentFeatures); !slices.Equal(got, disabled) {
		t.Fatal("current agent", got)
	}
	for _, f := range LegacyAgentFeatures {
		if !slices.Contains(AgentFeatures, f) {
			t.Fatal("legacy feature dropped", f)
		}
	}
	if !ValidFeatureNames(append(slices.Clone(AgentFeatures), "zz_future")) || ValidFeatureNames([]string{"b", "a"}) || ValidFeatureNames([]string{"Bad"}) || ValidFeatureNames([]string{"a", "a"}) {
		t.Fatal("feature name validation")
	}
}
