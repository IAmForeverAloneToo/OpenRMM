package agentupdate

import "testing"

// R10: the live service command is checked by shape, so service.ps1 feature
// changes keep updates working while any other executable, path or argument is
// still refused.
func TestTrustedServiceCommand(t *testing.T) {
	n := &MSIPlatform{target: `C:\Program Files\OpenRMM Agent\openrmm-agent.exe`, data: `C:\ProgramData\OpenRMM Agent`, state: `C:\ProgramData\OpenRMM Agent\state`}
	base := `"C:\Program Files\OpenRMM Agent\openrmm-agent.exe" -service -state "C:\ProgramData\OpenRMM Agent\state" -log-directory "C:\ProgramData\OpenRMM Agent\logs"`
	for _, ok := range []string{
		base,
		base + ` -inventory=true -inventory-interval 15m -disk-space=true -memory=true -cpu=true -uptime=true -services=true -event-logs=true -windows-updates=true -software=true -processes=true -scripts=true -desktop=true`,
		base + ` -inventory=true -inventory-interval 15m -disk-space=false -scripts=false`,
		base + ` -inventory=true -inventory-interval 15m -disk-space=true -memory=true -cpu=true -uptime=true -services=true -event-logs=true -windows-updates=true -software=true -processes=true -scripts=true -desktop=true -terminal=true -files=false`,
	} {
		if !n.trustedCommand(ok) {
			t.Fatal("feature configuration refused", ok)
		}
	}
	for _, bad := range []string{
		`"C:\Temp\openrmm-agent.exe" -service -state "C:\ProgramData\OpenRMM Agent\state" -log-directory "C:\ProgramData\OpenRMM Agent\logs"`,
		`"C:\Program Files\OpenRMM Agent\openrmm-agent.exe" -service -state "C:\Users\Public\state" -log-directory "C:\ProgramData\OpenRMM Agent\logs"`,
		base + ` -server https://attacker.example`,
		base + ` -desktop=true -scripts=true`, // switches out of the fixed order
		base + ` -files=true -terminal=true`,
		base + ` -scripts=maybe`,
		base + " -scripts=true\n",
		base + ` & calc.exe`,
	} {
		if n.trustedCommand(bad) {
			t.Fatal("untrusted service command accepted", bad)
		}
	}
}
