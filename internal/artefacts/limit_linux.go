package artefacts

import (
	"os/exec"
	"runtime/debug"
	"syscall"
)

// limitProcess bounds a parsing process: lower CPU priority, a heap target
// and an address space limit, so a crafted file can at worst end it.
func limitProcess() {
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
	_ = syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: addressMemory, Max: addressMemory})
	debug.SetMemoryLimit(softMemory)
}

// childAttrs ends the parsing process when the server ends.
func childAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
