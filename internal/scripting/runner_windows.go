package scripting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

func powerShell() string {
	p, e := windows.GetSystemDirectory()
	if e != nil {
		return ""
	}
	return filepath.Join(p, "WindowsPowerShell", "v1.0", "powershell.exe")
}
func Supported() bool {
	p := powerShell()
	if p == "" {
		return false
	}
	s, e := os.Stat(p)
	return e == nil && !s.IsDir()
}

type outputBuffer struct {
	mu        sync.Mutex
	b         []byte
	truncated bool
}

func (b *outputBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), MaxOutput-len(b.b))
	b.b = append(b.b, p[:n]...)
	b.truncated = b.truncated || n < len(p)
	return len(p), nil
}
func (b *outputBuffer) text() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.ToValidUTF8(string(b.b), "�")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return ' '
		}
		return r
	}, s)
	if len(s) > MaxOutput {
		s = s[:MaxOutput]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		b.truncated = true
	}
	return s, b.truncated
}

const wrapper = `param([string]$InputFile)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$data = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$values = @{}
foreach ($property in $data.arguments.PSObject.Properties) { $values[$property.Name] = [string]$property.Value }
$global:LASTEXITCODE = 0
try {
    & $data.script @values
    $invokeSucceeded = $?
    if ($global:LASTEXITCODE -ne 0) { exit $global:LASTEXITCODE }
    if (-not $invokeSucceeded) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.ToString())
    exit 1
}
`

func writePS(path, body string) error {
	return os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(body)...), 0600)
}

// WorkerMain receives no executable request until its parent has assigned it
// to a kill-on-close Job Object. There is no network or enrollment in this mode.
func WorkerMain() int {
	b, e := io.ReadAll(io.LimitReader(os.Stdin, MaxBytes+1))
	var q protocol.ScriptJob
	if e != nil {
		return 80
	}
	if Decode(b, &q) != nil {
		return 81
	}
	if !JobValid(q) {
		return 82
	}
	// The worker runs with the agent's own identity (SYSTEM when installed);
	// the stored run-as value no longer selects an account.
	result := nativeRun(context.Background(), q)
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
func nativeRun(ctx context.Context, q protocol.ScriptJob) protocol.ScriptResult {
	r := Failure(q.ID, "start_failed")
	if !Supported() {
		return Failure(q.ID, "unsupported")
	}
	dir, e := os.MkdirTemp(".", "script-")
	if e != nil {
		return r
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		return r
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "body.ps1")
	entry := filepath.Join(dir, "invoke.ps1")
	input := filepath.Join(dir, "input.json")
	if writePS(script, q.Version.Definition.Body) != nil || writePS(entry, wrapper) != nil {
		return r
	}
	b, _ := json.Marshal(struct {
		Script    string            `json:"script"`
		Arguments map[string]string `json:"arguments"`
	}{script, q.Arguments})
	if os.WriteFile(input, b, 0600) != nil {
		return r
	}
	c := exec.CommandContext(ctx, powerShell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", entry, "-InputFile", input)
	c.Dir = dir
	c.SysProcAttr = &windowsSysProcAttr
	c.WaitDelay = time.Second
	root, _ := windows.GetWindowsDirectory()
	sys, _ := windows.GetSystemDirectory()
	// PATHEXT lets scripts call programs by name (whoami, ipconfig).
	c.Env = []string{"SystemRoot=" + root, "WINDIR=" + root, "TEMP=" + dir, "TMP=" + dir, "PATH=" + sys + ";" + filepath.Dir(powerShell()), "PATHEXT=.COM;.EXE;.BAT;.CMD", "ComSpec=" + filepath.Join(sys, "cmd.exe")}
	out, errout := &outputBuffer{}, &outputBuffer{}
	c.Stdout = out
	c.Stderr = errout
	if e = c.Run(); e != nil && c.ProcessState == nil {
		return r
	}
	code := int32(c.ProcessState.ExitCode())
	r.ExitCode = &code
	r.Outcome = "succeeded"
	if code != 0 {
		r.Outcome = "failed"
	}
	r.Stdout, r.Truncated = out.text()
	var trunc bool
	r.Stderr, trunc = errout.text()
	r.Truncated = r.Truncated || trunc
	return r
}

// RunContained executes only this application's fixed worker, then allows the
// approved definition through stdin after process-tree lifetime limits apply.
func RunContained(ctx context.Context, state string, q protocol.ScriptJob) protocol.ScriptResult {
	if !JobValid(q) {
		return Failure(q.ID, "denied")
	}
	if !Supported() {
		return Failure(q.ID, "unsupported")
	}
	ctx, stop := context.WithTimeout(ctx, time.Duration(q.Version.Definition.Timeout)*time.Second)
	defer stop()
	exe, e := os.Executable()
	if e != nil {
		return Failure(q.ID, "start_failed")
	}
	work := filepath.Join(state, "script-work")
	if os.MkdirAll(work, 0700) != nil {
		return Failure(q.ID, "start_failed")
	}
	work, e = os.MkdirTemp(work, q.ID+"-")
	if e != nil {
		return Failure(q.ID, "start_failed")
	}
	defer os.RemoveAll(work)
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return Failure(q.ID, "start_failed")
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.BasicLimitInformation.ActiveProcessLimit = 16
	limits.JobMemoryLimit = 512 * 1024 * 1024
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return Failure(q.ID, "start_failed")
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(child, exe, "--script-worker")
	c.Dir = work
	c.SysProcAttr = &windowsSysProcAttr
	c.WaitDelay = time.Second
	c.Stderr = io.Discard
	stdin, e := c.StdinPipe()
	if e != nil {
		return Failure(q.ID, "start_failed")
	}
	defer stdin.Close()
	var output bytes.Buffer
	c.Stdout = &boundedJSON{buffer: &output}
	if e = c.Start(); e != nil {
		return Failure(q.ID, "start_failed")
	}
	p, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if e == nil {
		e = windows.AssignProcessToJobObject(job, p)
		windows.CloseHandle(p)
	}
	if e != nil {
		cancel()
		_ = c.Wait()
		return Failure(q.ID, "start_failed")
	}
	raw, _ := json.Marshal(q)
	_, e = stdin.Write(raw)
	_ = stdin.Close()
	if e != nil {
		cancel()
	}
	// Closing the job handle on cancellation kills ordinary descendants, including
	// processes holding redirected output open. It does not undo script effects.
	done := make(chan struct{})
	killerDone := make(chan struct{})
	go func() {
		defer close(killerDone)
		select {
		case <-ctx.Done():
			_ = windows.TerminateJobObject(job, 1)
		case <-done:
		}
	}()
	e = c.Wait()
	close(done)
	<-killerDone
	if ctx.Err() != nil {
		outcome := "cancelled"
		if ctx.Err() == context.DeadlineExceeded {
			outcome = "timed_out"
		}
		return Failure(q.ID, outcome)
	}
	var r protocol.ScriptResult
	if e != nil || Decode(output.Bytes(), &r) != nil || !ResultValid(r) || r.ID != q.ID || r.Outcome == "running" {
		failure := Failure(q.ID, "unknown")
		code := -1
		if c.ProcessState != nil {
			code = c.ProcessState.ExitCode()
		}
		failure.Stderr = fmt.Sprintf("The execution worker did not return a valid result (worker exit %d; response bytes %d).", code, output.Len())
		return failure
	}
	return r
}

type boundedJSON struct{ buffer *bytes.Buffer }

func (b *boundedJSON) Write(p []byte) (int, error) {
	if len(p) > MaxBytes-b.buffer.Len() {
		return 0, ErrInvalid
	}
	return b.buffer.Write(p)
}
