package agent

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// machineProxy agrees with netsh about whether WinHTTP has a proxy.
func TestMachineProxyMatchesNetsh(t *testing.T) {
	system, _ := windows.GetSystemDirectory()
	out, err := exec.Command(filepath.Join(system, "netsh.exe"), "winhttp", "show", "proxy").Output()
	if err != nil {
		t.Skip("netsh unavailable")
	}
	direct := strings.Contains(string(out), "Direct access")
	if got := machineProxy(); (got.url == nil) != direct {
		t.Fatalf("machineProxy() = %v; netsh says direct=%v", got.url, direct)
	}
}
