package terminal

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

type nativeShell struct {
	mu                    sync.Mutex
	input                 *os.File
	output                *os.File
	buffer                []byte
	ended                 bool
	once                  sync.Once
	job, pc, process      windows.Handle
	readDone, processDone chan struct{}
	work                  string
}

// Identity is the account the shell runs as: SYSTEM for the installed agent,
// the signed-in user for console diagnostics.
func Identity() (string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", ErrUnavailable
	}
	v := windows.RtlGetVersion()
	if v.MajorVersion < 10 || v.BuildNumber < 17763 {
		return "", ErrUnavailable
	}
	sys, e := windows.GetSystemDirectory()
	if e != nil {
		return "", ErrUnavailable
	}
	if _, e = os.Stat(filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")); e != nil {
		return "", ErrUnavailable
	}
	return u.User.Sid.String(), nil
}

func Start(state string) (Shell, error) {
	if _, e := Identity(); e != nil {
		return nil, e
	}
	// Windows process launchers can leave the inheritable ignore-CTRL+C bit
	// set, independently of Go's registered signal handlers. Restore normal
	// processing in this process so the new console shell does not inherit it.
	control := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
	if ok, _, _ := control.Call(0, 0); ok == 0 {
		return nil, ErrUnavailable
	}
	work, e := os.MkdirTemp(state, "terminal-")
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &nativeShell{work: work, readDone: make(chan struct{}), processDone: make(chan struct{})}
	var inRead, outWrite windows.Handle
	cleanup := func() {
		if inRead != 0 {
			windows.CloseHandle(inRead)
			inRead = 0
		}
		if outWrite != 0 {
			windows.CloseHandle(outWrite)
			outWrite = 0
		}
	}
	defer cleanup()
	failed := true
	defer func() {
		if failed {
			cleanup()
			s.Close()
		}
	}()
	s.job, e = windows.CreateJobObject(nil, nil)
	if e != nil {
		return nil, ErrUnavailable
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.BasicLimitInformation.ActiveProcessLimit = 16
	limits.JobMemoryLimit = 512 * 1024 * 1024
	if _, e = windows.SetInformationJobObject(s.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
		return nil, ErrUnavailable
	}
	var inWrite, outRead windows.Handle
	if e = windows.CreatePipe(&inRead, &inWrite, nil, 0); e != nil {
		return nil, ErrUnavailable
	}
	s.input = os.NewFile(uintptr(inWrite), "terminal-input")
	if e = windows.CreatePipe(&outRead, &outWrite, nil, 0); e != nil {
		return nil, ErrUnavailable
	}
	s.output = os.NewFile(uintptr(outRead), "terminal-output")
	if e = windows.CreatePseudoConsole(windows.Coord{X: Columns, Y: Rows}, inRead, outWrite, 0, &s.pc); e != nil {
		return nil, ErrUnavailable
	}
	// Drain independently before CreateProcess/ClosePseudoConsole: ConPTY may
	// synchronously emit output while starting or closing, including on old builds.
	go s.read()
	attrs, e := windows.NewProcThreadAttributeList(2)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer attrs.Delete()
	// This attribute takes HPCON itself as lpValue, unlike JOB_LIST's pointer
	// to a handle array. Keep the opaque native value as uintptr at the syscall
	// boundary instead of manufacturing a Go pointer from a numeric handle.
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	if ok, _, _ := update.Call(uintptr(unsafe.Pointer(attrs.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(s.pc), unsafe.Sizeof(s.pc), 0, 0); ok == 0 {
		return nil, ErrUnavailable
	}
	// PROC_THREAD_ATTRIBUTE_JOB_LIST (Win10+) atomically assigns the process at
	// creation. No executable thread or suspended orphan exists outside this job.
	jobs := [1]windows.Handle{s.job}
	const jobList = 0x0002000d
	if e = attrs.Update(jobList, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs)); e != nil {
		return nil, ErrUnavailable
	}
	sys, _ := windows.GetSystemDirectory()
	root, _ := windows.GetWindowsDirectory()
	exe := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	app, _ := windows.UTF16PtrFromString(exe)
	cmd, _ := windows.UTF16PtrFromString(`"` + exe + `" -NoLogo -NoProfile -NoExit -Command "Remove-Module PSReadLine -ErrorAction SilentlyContinue"`)
	dir, _ := windows.UTF16PtrFromString(work)
	var environment []uint16
	for _, v := range []string{"SystemRoot=" + root, "WINDIR=" + root, "TEMP=" + work, "TMP=" + work, "PATH=" + sys + ";" + filepath.Dir(exe)} {
		b, _ := windows.UTF16FromString(v)
		environment = append(environment, b...)
	}
	environment = append(environment, 0)
	// Null standard handles with USESTDHANDLES prevent Windows from duplicating
	// a redirected parent's non-console handles into this ConPTY child.
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES}, ProcThreadAttributeList: attrs.List()}
	var pi windows.ProcessInformation
	e = windows.CreateProcess(app, cmd, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &environment[0], dir, &si.StartupInfo, &pi)
	runtime.KeepAlive(jobs)
	runtime.KeepAlive(environment)
	if e != nil {
		return nil, ErrUnavailable
	}
	windows.CloseHandle(pi.Thread)
	s.process = pi.Process
	windows.CloseHandle(inRead)
	inRead = 0
	windows.CloseHandle(outWrite)
	outWrite = 0
	go func() {
		defer close(s.processDone)
		_, _ = windows.WaitForSingleObject(s.process, windows.INFINITE)
		s.mu.Lock()
		s.ended = true
		s.mu.Unlock()
	}()
	failed = false
	return s, nil
}
func (s *nativeShell) read() {
	defer close(s.readDone)
	b := make([]byte, 4096)
	for {
		n, e := s.output.Read(b)
		if n > 0 {
			s.mu.Lock()
			if len(s.buffer)+n > MaxPending {
				s.ended = true
			} else {
				s.buffer = append(s.buffer, b[:n]...)
			}
			s.mu.Unlock()
		}
		if e != nil {
			return
		}
	}
}
func (s *nativeShell) Input(b []byte) error {
	if len(b) == 0 || len(b) > MaxInput {
		return ErrInvalid
	}
	_, e := s.input.Write(b)
	return e
}
func (s *nativeShell) Drain() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(len(s.buffer), MaxChunk)
	b := append([]byte(nil), s.buffer[:n]...)
	clear(s.buffer[:n])
	s.buffer = append([]byte(nil), s.buffer[n:]...)
	return b, s.ended
}
func (s *nativeShell) Close() {
	s.once.Do(func() {
		if s.job != 0 {
			_ = windows.TerminateJobObject(s.job, 1)
			windows.CloseHandle(s.job)
		}
		if s.pc != 0 {
			windows.ClosePseudoConsole(s.pc)
		}
		if s.input != nil {
			_ = s.input.Close()
		}
		if s.output != nil {
			_ = s.output.Close()
		}
		if s.pc != 0 {
			select {
			case <-s.readDone:
			case <-time.After(2 * time.Second):
			}
		}
		if s.process != 0 {
			select {
			case <-s.processDone:
			case <-time.After(2 * time.Second):
			}
			windows.CloseHandle(s.process)
		}
		if s.work != "" {
			_ = os.Remove(s.work)
		} // never recursively delete a command-controlled directory
		s.mu.Lock()
		clear(s.buffer)
		s.buffer = nil
		s.ended = true
		s.mu.Unlock()
	})
}
