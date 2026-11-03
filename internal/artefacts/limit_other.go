//go:build !linux

package artefacts

import (
	"os/exec"
	"runtime/debug"
)

// limitProcess sets the heap target only: servers run on Linux, and other
// systems (development) get no address space limit.
func limitProcess() { debug.SetMemoryLimit(softMemory) }

func childAttrs(*exec.Cmd) {}
