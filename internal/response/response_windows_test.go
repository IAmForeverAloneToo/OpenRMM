package response

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func run(t *testing.T, a protocol.ResponseAction, cache *HashCache) protocol.ActionResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, e := Run(ctx, a, cache)
	if e != nil {
		t.Fatal(a.Kind, e)
	}
	if r.Format != protocol.ActionFormat || r.Action.Text() != a.Text() {
		t.Fatal("result header", r.Format, r.Action)
	}
	return r
}

// The read-only actions describe the local machine, including things the
// test creates itself.
func TestReadOnlyActions(t *testing.T) {
	cache := &HashCache{}
	r := run(t, protocol.ResponseAction{Kind: "processes"}, cache)
	self := os.Getpid()
	var me protocol.ProcessDetail
	for _, p := range r.Processes {
		if int(p.PID) == self {
			me = p
		}
	}
	exe, _ := os.Executable()
	if !strings.EqualFold(me.Image, exe) || len(me.SHA256) != 64 || me.Start == "" || me.StartedAt == "" || !strings.Contains(me.CommandLine, "-test") || me.UserSID == "" || me.ParentPID == 0 {
		t.Fatalf("own process %+v", me)
	}
	if len(r.Processes) < 20 {
		t.Fatal("too few processes", len(r.Processes))
	}

	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	listening := uint16(l.Addr().(*net.TCPAddr).Port)
	r = run(t, protocol.ResponseAction{Kind: "connections"}, cache)
	found := false
	for _, c := range r.Connections {
		if c.Protocol == "tcp" && c.LocalPort == listening && c.LocalAddress == "127.0.0.1" && c.State == "listen" && int(c.PID) == self {
			found = true
		}
	}
	if !found {
		t.Fatal("own listener missing from", len(r.Connections), "connections")
	}

	r = run(t, protocol.ResponseAction{Kind: "services"}, cache)
	var eventlog protocol.ServiceDetail
	for _, s := range r.Services {
		if strings.EqualFold(s.Name, "EventLog") {
			eventlog = s
		}
	}
	if eventlog.State != "running" || eventlog.StartType != "automatic" || !strings.HasSuffix(strings.ToLower(eventlog.Image), "svchost.exe") || len(eventlog.SHA256) != 64 || !strings.HasSuffix(strings.ToLower(eventlog.ServiceDLL), "wevtsvc.dll") || len(eventlog.DLLSHA256) != 64 {
		t.Fatalf("EventLog service %+v", eventlog)
	}

	r = run(t, protocol.ResponseAction{Kind: "tasks"}, cache)
	withActions := 0
	for _, task := range r.Tasks {
		if len(task.Actions) > 0 && len(task.SHA256) == 64 && strings.HasPrefix(task.Path, `\`) {
			withActions++
		}
	}
	// The task folder is readable only by administrators (the agent runs as
	// SYSTEM); an unelevated test run cannot see it.
	if withActions < 5 && elevated() {
		t.Fatal("scheduled tasks", len(r.Tasks), withActions, r.Notes)
	}

	r = run(t, protocol.ResponseAction{Kind: "registry", Key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`}, cache)
	product := ""
	for _, v := range r.Registry.Values {
		if v.Name == "ProductName" {
			product = v.Data
		}
	}
	if !strings.HasPrefix(product, "Windows") || r.Registry.LastWrite == "" || len(r.Registry.Subkeys) == 0 {
		t.Fatalf("registry %+v", r.Registry)
	}
	if _, e := Run(context.Background(), protocol.ResponseAction{Kind: "registry", Key: `HKLM\SOFTWARE\OpenRMM-no-such-key`}, cache); e != ErrNotFound {
		t.Fatal("missing key", e)
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		r = run(t, protocol.ResponseAction{Kind: "registry", Key: `HKLM\SAM\SAM`}, cache)
		if !r.Registry.BackupPrivilege || len(r.Registry.Subkeys) == 0 {
			t.Fatalf("SAM with the backup privilege %+v", r.Registry)
		}
	}
}

// A process tree the test starts is killed children first; a changed
// identity and protected processes are refused.
func TestKillTree(t *testing.T) {
	cmd := exec.Command(os.Getenv("ComSpec"), "/c", "ping", "-n", "60", "127.0.0.1")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	cache := &HashCache{}
	var root, child protocol.ProcessDetail
	for i := 0; i < 50 && child.PID == 0; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, p := range run(t, protocol.ResponseAction{Kind: "processes"}, cache).Processes {
			if int(p.PID) == cmd.Process.Pid {
				root = p
			}
			if root.PID != 0 && p.ParentPID == root.PID && strings.EqualFold(p.Name, "PING.EXE") {
				child = p
			}
		}
	}
	if child.PID == 0 || !root.CanKill || !child.CanKill {
		t.Fatalf("test tree not found or not killable: %+v %+v", root, child)
	}
	wrong := protocol.ResponseAction{Kind: "kill", PID: root.PID, Start: root.Start + "1", Name: root.Name, Tree: true}
	if k := run(t, wrong, cache).Killed; len(k) != 1 || k[0].Outcome != "identity_changed" {
		t.Fatalf("changed identity %+v", k)
	}
	// The real lsass is only checked read-only; it is never targeted.
	for _, p := range run(t, protocol.ResponseAction{Kind: "processes"}, cache).Processes {
		if strings.EqualFold(p.Name, "lsass.exe") && p.CanKill {
			t.Fatal("lsass is killable")
		}
	}
	a := protocol.ResponseAction{Kind: "kill", PID: root.PID, Start: root.Start, Name: root.Name, Tree: true}
	k := run(t, a, cache).Killed
	// The shell may exit on its own once its child has ended.
	if len(k) != 2 || k[0].PID != child.PID || k[1].PID != root.PID || k[0].Outcome != "succeeded" || k[1].Outcome != "succeeded" && k[1].Outcome != "exited" || len(k[0].SHA256) != 64 || len(k[1].SHA256) != 64 {
		t.Fatalf("tree kill %+v", k)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("root still running")
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, child.PID)
	if e == nil {
		s, _ := windows.WaitForSingleObject(h, 0)
		windows.CloseHandle(h)
		if s != windows.WAIT_OBJECT_0 {
			t.Fatal("child " + strconv.FormatUint(uint64(child.PID), 10) + " still running")
		}
	}
}

// A protected name outside the system folder (a
// disguised process) can be killed; the genuine one cannot. Only a copy the
// test starts is ever ended; the real svchost is checked read-only.
func TestKillDisguisedProcess(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "svchost.exe")
	src, e := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(fake, src, 0700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(fake, "-n", "60", "127.0.0.1")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Process.Kill()
	cache := &HashCache{}
	var mine, genuine protocol.ProcessDetail
	for i := 0; i < 50 && mine.PID == 0; i++ {
		time.Sleep(100 * time.Millisecond)
		for _, p := range run(t, protocol.ResponseAction{Kind: "processes"}, cache).Processes {
			if int(p.PID) == cmd.Process.Pid {
				mine = p
			}
			if strings.EqualFold(p.Name, "svchost.exe") && strings.HasPrefix(strings.ToLower(p.Image), strings.ToLower(os.Getenv("SystemRoot"))) {
				genuine = p
			}
		}
	}
	if !mine.CanKill || genuine.PID == 0 || genuine.CanKill {
		t.Fatalf("disguised %+v genuine %+v", mine, genuine)
	}
	k := run(t, protocol.ResponseAction{Kind: "kill", PID: mine.PID, Start: mine.Start, Name: mine.Name}, cache).Killed
	if len(k) != 1 || k[0].Outcome != "succeeded" || len(k[0].SHA256) != 64 {
		t.Fatalf("disguised kill %+v", k)
	}
}

// elevated reports whether the test runs with an administrator token.
func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
