package processes

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestProcessFixture(t *testing.T) {
	if os.Getenv("OPENRMM_OWNED_PROCESS_FIXTURE") == "1" {
		time.Sleep(3 * time.Minute)
		os.Exit(0)
	}
}
func ownedProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c := exec.Command(exe, "-test.run=^TestProcessFixture$")
	c.Env = append(os.Environ(), "OPENRMM_OWNED_PROCESS_FIXTURE=1")
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	return c
}
func TestNativeSnapshotAndGuardedOwnedTermination(t *testing.T) {
	if unsafe.Sizeof(memoryCounters{}) != 72 {
		t.Fatal("native memory structure ABI")
	}
	c := ownedProcess(t)
	pid := uint32(c.Process.Pid)
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		t.Fatal(e)
	}
	start, _, e := counters(h)
	windows.CloseHandle(h)
	if e != nil {
		t.Fatal(e)
	}
	n := native{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, e := n.Collect(ctx)
	if e != nil || !Valid(v) {
		t.Fatal("native snapshot", e)
	}
	found := false
	for _, p := range v.Items {
		if p.PID == pid {
			found = true
			if p.Start != start || p.Memory == nil || p.CPU == nil || !p.CanTerminate {
				t.Fatal("owned metrics/permissions", p)
			}
		}
	}
	if !found {
		t.Fatal("fixture absent")
	}
	self, _ := os.Executable()
	a := protocol.ProcessAction{ID: strings.Repeat("a", 32), PID: pid, Start: "1234", Name: filepath.Base(self)}
	// A stale identity must never terminate the fixture.
	if r := n.Execute(ctx, a); r.Outcome != "identity_changed" {
		t.Fatal("PID reuse not guarded", r)
	}
	a.Start = start
	canceled, stop := context.WithCancel(ctx)
	stop()
	if r := n.Execute(canceled, a); r.Outcome != "interrupted" {
		t.Fatal("cancel ignored")
	}
	if Manageable(uint32(os.Getpid()), filepath.Base(self)) && safe(windows.CurrentProcess(), uint32(os.Getpid()), filepath.Base(self)) {
		t.Fatal("own process accepted")
	}
	if r := n.Execute(ctx, protocol.ProcessAction{ID: a.ID, PID: 4, Start: start, Name: "System"}); r.Outcome != "denied" {
		t.Fatal("system process accepted", r)
	}
	if r := n.Execute(ctx, a); r.Outcome != "succeeded" {
		t.Fatal("owned termination", r)
	}
	if e = c.Wait(); e == nil {
		t.Fatal("fixture did not terminate abnormally")
	}
}
