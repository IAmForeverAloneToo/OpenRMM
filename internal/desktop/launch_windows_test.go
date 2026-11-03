package desktop

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A companion whose file an install replaced (renamed aside, as Windows
// Installer does with a running file) is ended; the installed one counts as
// running in its session, and one started from another folder is left alone.
// Harmless copies of ping.exe stand in for the companion.
func TestReplacedCompanionsEnd(t *testing.T) {
	var session uint32
	if windows.ProcessIdToSessionId(uint32(os.Getpid()), &session) != nil || session == 0 {
		t.Skip("needs a signed-in user session (not a service session)")
	}
	ping, e := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"))
	if e != nil {
		t.Skip("ping.exe not readable", e)
	}
	installed, other := t.TempDir(), t.TempDir()
	exe := filepath.Join(installed, "openrmm-desktop.exe")
	start := func(path string) *exec.Cmd {
		if e := os.WriteFile(path, ping, 0700); e != nil {
			t.Fatal(e)
		}
		c := exec.Command(path, "-n", "60", "127.0.0.1")
		if e := c.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Process.Kill(); c.Wait() })
		return c
	}
	old := start(exe)
	// The install moves the running file aside and puts the new one in place.
	if e := os.Rename(exe, filepath.Join(installed, "moved.rbf")); e != nil {
		t.Fatal(e)
	}
	current := start(exe)
	elsewhere := start(filepath.Join(other, "openrmm-desktop.exe"))
	missing, ended := sessionsWithoutCompanion(exe)
	if ended != 1 || slices.Contains(missing, session) {
		t.Fatalf("ended %d, sessions without a companion %v (this one %d)", ended, missing, session)
	}
	done := make(chan error, 1)
	go func() { done <- old.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the replaced companion still runs")
	}
	for _, c := range []*exec.Cmd{current, elsewhere} {
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(c.Process.Pid))
		var code uint32
		if e == nil {
			e = windows.GetExitCodeProcess(h, &code)
			windows.CloseHandle(h)
		}
		if e != nil || code != 259 { // STILL_ACTIVE
			t.Fatal("a current companion was ended", e, code)
		}
	}
	if replaced(exe, exe) || replaced(filepath.Join(other, "openrmm-desktop.exe"), exe) || !replaced(filepath.Join(installed, "moved.rbf"), exe) || !replaced(filepath.Join(other, "gone", "openrmm-desktop.exe"), exe) {
		t.Fatal("replaced")
	}
}
