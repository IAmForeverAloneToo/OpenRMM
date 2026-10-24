package agent

import (
	"golang.org/x/sys/windows/registry"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// policyLocks reads HKLM\SOFTWARE\Policies\OpenRMM\Agent: a DWORD named after
// a feature with value 0 locks that feature off (settable by Group Policy or
// scripts/service.ps1 -Action configure; it survives MSI upgrades).
func policyLocks() map[string]bool {
	out := map[string]bool{}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\OpenRMM\Agent`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if e != nil {
		return out
	}
	defer k.Close()
	for _, f := range protocol.AgentFeatures {
		if v, _, e := k.GetIntegerValue(f); e == nil && v == 0 {
			out[f] = true
		}
	}
	return out
}
