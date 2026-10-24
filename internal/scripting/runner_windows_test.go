package scripting

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--script-worker" {
		os.Exit(WorkerMain())
	}
	os.Exit(m.Run())
}

func TestCancellationEndsOwnedChild(t *testing.T) {
	q := testJob()
	q.Version.Definition.Timeout = 30
	q.Version.Definition.Body = `param([string]$Message)
$child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList '-NoLogo -NoProfile -NonInteractive -Command Start-Sleep -Seconds 60' -WindowStyle Hidden -PassThru
[IO.File]::WriteAllText($Message,[string]$child.Id)
Start-Sleep -Seconds 60`
	q.Version.Hash = Digest(q.Version)
	state := t.TempDir()
	marker := filepath.Join(state, "owned-child.txt")
	q.Arguments["Message"] = marker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan protocol.ScriptResult, 1)
	go func() { done <- RunContained(ctx, state, q) }()
	deadline := time.Now().Add(10 * time.Second)
	var raw []byte
	var e error
	for time.Now().Before(deadline) {
		raw, e = os.ReadFile(marker)
		if e == nil && len(raw) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e != nil || len(raw) == 0 {
		t.Fatal("owned child did not start")
	}
	pid, e := strconv.ParseUint(string(raw), 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	cancel()
	select {
	case r := <-done:
		if r.Outcome != "cancelled" {
			t.Fatal(r.Outcome)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runner cancellation did not finish")
	}
	result, e := windows.WaitForSingleObject(h, 3000)
	if e != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatal("owned child escaped ordinary process-tree cleanup", e)
	}
}
func TestNativePowerShellDataOutputAndContainment(t *testing.T) {
	if !Supported() {
		t.Fatal("Windows PowerShell unavailable")
	}
	q := testJob()
	q.Version.Definition.Timeout = 10
	q.Version.Hash = Digest(q.Version)
	value := "literal '; Write-Output INJECTED; # $(Write-Output injected) `\" 日本語 <script> & |"
	q.Arguments["Message"] = value
	r := RunContained(context.Background(), t.TempDir(), q)
	if r.Outcome != "succeeded" || r.ExitCode == nil || *r.ExitCode != 0 || strings.TrimSpace(r.Stdout) != value {
		t.Fatalf("parameter data not preserved: %#v", r)
	}
	q.Version.Definition.Body = "[Console]::Error.WriteLine('expected error'); exit 7"
	q.Version.Definition.Parameters = q.Version.Definition.Parameters[:0]
	q.Arguments = map[string]string{}
	q.Version.Hash = Digest(q.Version)
	r = RunContained(context.Background(), t.TempDir(), q)
	if r.Outcome != "failed" || r.ExitCode == nil || *r.ExitCode != 7 || !strings.Contains(r.Stderr, "expected error") {
		t.Fatal("exit/stderr", r)
	}
	// Programs are found by name (PATHEXT is set).
	q.Version.Definition.Body = "whoami"
	q.Version.Hash = Digest(q.Version)
	if r = RunContained(context.Background(), t.TempDir(), q); r.Outcome != "succeeded" || !strings.Contains(r.Stdout, `\`) {
		t.Fatal("program by name", r)
	}
	q.Version.Definition.Body = "[Console]::Write(('x' * 200000)); [Console]::Error.Write(('y' * 200000))"
	q.Version.Hash = Digest(q.Version)
	r = RunContained(context.Background(), t.TempDir(), q)
	if r.Outcome != "succeeded" || len(r.Stdout) != MaxOutput || len(r.Stderr) != MaxOutput || !r.Truncated {
		t.Fatal("bounded output", r.Outcome, len(r.Stdout), len(r.Stderr))
	}
	q.Version.Definition.Body = "Start-Sleep -Seconds 60"
	q.Version.Hash = Digest(q.Version)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(500*time.Millisecond, cancel)
	start := time.Now()
	r = RunContained(ctx, t.TempDir(), q)
	if r.Outcome != "cancelled" || time.Since(start) > 5*time.Second {
		t.Fatal("cancellation containment", r)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	r = RunContained(ctx, t.TempDir(), q)
	if r.Outcome != "timed_out" {
		t.Fatal("deadline", r)
	}
}
