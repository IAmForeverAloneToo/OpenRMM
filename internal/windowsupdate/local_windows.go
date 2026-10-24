package windowsupdate

import (
	"bufio"
	"context"
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"
)

// WorkerFlag runs one Windows Update job in a child process of the agent.
const WorkerFlag = "--update-worker"

// local runs the broker inside the agent (one SYSTEM agent). The
// broker keeps its journal, so interrupted work is still reported as Unknown
// and never replayed; installation and restart are allowed because server-side
// permissions decide.
type local struct{ b *Broker }

func NewLocal(ctx context.Context, journal string) (Adapter, error) {
	b, e := NewBroker(ctx, journal, worker{}, true, true)
	if e != nil {
		return nil, e
	}
	return local{b}, nil
}
func (l local) Probe(context.Context) (protocol.UpdateSupport, error) {
	r := l.b.Handle(IPCRequest{Op: "probe"})
	if r.Error != "" || !SupportValid(r.Support) {
		return protocol.UpdateSupport{}, ErrInvalid
	}
	return r.Support, nil
}
func (l local) Submit(_ context.Context, q protocol.UpdateJob) (protocol.UpdateProgress, error) {
	r := l.b.Handle(IPCRequest{Op: "submit", Job: &q})
	if r.Progress == nil {
		return Failure(q, "blocked"), nil
	}
	return *r.Progress, nil
}
func (l local) Status(_ context.Context, id string) (protocol.UpdateProgress, error) {
	r := l.b.Handle(IPCRequest{Op: "status", ID: id})
	if r.Progress == nil {
		return protocol.UpdateProgress{}, ErrInvalid
	}
	return *r.Progress, nil
}

// worker executes each job in a child process of the agent executable, held
// in a kill-on-close job object, so a stuck Windows Update call cannot outlive
// the agent and COM state never mixes with the agent process.
type worker struct{}

func (worker) Run(ctx context.Context, q protocol.UpdateJob, emit func(protocol.UpdateProgress) error) {
	exe, e := os.Executable()
	if e != nil {
		return
	}
	data, _ := json.Marshal(q)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := exec.CommandContext(childCtx, exe, WorkerFlag)
	c.Dir = filepath.Dir(exe)
	c.Stderr = io.Discard
	input, e := c.StdinPipe()
	if e != nil {
		return
	}
	defer input.Close()
	stdout, e := c.StdoutPipe()
	if e != nil {
		return
	}
	// A worker receives no request until it belongs to the job object. If the
	// agent exits before assignment, stdin closes without a request; if it
	// exits afterward, Windows terminates the contained worker.
	job, e := windows.CreateJobObject(nil, nil)
	if e != nil {
		return
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return
	}
	if c.Start() != nil {
		return
	}
	if e = assignWorker(job, uint32(c.Process.Pid)); e != nil {
		cancel()
		_ = c.Wait()
		return
	}
	if _, e = input.Write(data); e != nil || input.Close() != nil {
		cancel()
		_ = c.Wait()
		return
	}
	s := bufio.NewScanner(stdout)
	s.Buffer(make([]byte, 4096), MaxBytes)
	for s.Scan() {
		var p protocol.UpdateProgress
		if Decode(s.Bytes(), &p) != nil || !ProgressValid(p, q) || emit(p) != nil {
			cancel()
			break
		}
	}
	_ = c.Wait()
}

func assignWorker(job windows.Handle, pid uint32) error {
	p, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(p)
	return windows.AssignProcessToJobObject(job, p)
}

// WorkerMain is the child side: one validated job from stdin, progress lines
// on stdout. It accepts no paths, executables or search criteria.
func WorkerMain() int {
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	var q protocol.UpdateJob
	if e != nil || len(b) > 8192 || Decode(b, &q) != nil || !JobValid(q) {
		return 87
	}
	NativeRun(context.Background(), q, func(p protocol.UpdateProgress) error { return json.NewEncoder(os.Stdout).Encode(p) })
	return 0
}
