package agentupdate

import (
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"testing"
)

func TestUpdaterExitChild(t *testing.T) {
	if os.Getenv("OPENRMM_EXIT_TEST_CHILD") != "1" {
		t.Skip("owned child")
	}
	if _, e := io.ReadFull(os.Stdin, make([]byte, 1)); e != nil {
		os.Exit(2)
	}
}
func TestExitProofNeedsOnlyLimitedQuery(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(exe, "-test.run=^TestUpdaterExitChild$")
	child.Env = append(os.Environ(), "OPENRMM_EXIT_TEST_CHILD=1")
	input, e := child.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		input.Close()
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(child.Process.Pid))
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	if exited, e := processExited(h); e != nil || exited {
		t.Fatal("running child reported exited", e)
	}
	if _, e := input.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	input.Close()
	if e = child.Wait(); e != nil {
		t.Fatal(e)
	}
	if exited, e := processExited(h); e != nil || !exited {
		t.Fatal("pinned child exit not observed", e)
	}
}
