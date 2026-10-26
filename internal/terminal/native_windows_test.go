package terminal

import (
	"golang.org/x/sys/windows"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// Only owned PowerShell and its inert sleep child are started. No services,
// downloads, privileged actions or external machine state are touched.
func TestNativePersistentPowerShellReadHostInterruptAndProcessJob(t *testing.T) {
	if _, e := Identity(); e != nil {
		t.Skip("supported non-SYSTEM Windows account required")
	}
	shell, e := Start(t.TempDir())
	if e != nil {
		t.Fatal("ConPTY startup", e)
	}
	defer shell.Close()
	s := shell.(*nativeShell)
	collect := func(marker string) {
		t.Helper()
		var output strings.Builder
		// Generous: Windows PowerShell can start slowly on a cold machine (CI).
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			b, ended := s.Drain()
			output.Write(b)
			if strings.Contains(output.String(), marker) {
				return
			}
			if ended {
				var code uint32
				_ = windows.GetExitCodeProcess(s.process, &code)
				t.Fatalf("shell exited before %s (exit %d; owned output %q)", marker, code, output.String())
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("missing live output %s; owned fixture output %q", marker, output.String())
	}
	collect("PS ")
	if e = s.Input([]byte("$rmmValue=39; Write-Output ('RMM'+($rmmValue+3))\r")); e != nil {
		t.Fatal(e)
	}
	collect("RMM42")
	_ = s.Input([]byte("Write-Output ('KEEP'+$rmmValue)\r"))
	collect("KEEP39")
	_ = s.Input([]byte("$answer=Read-Host 'RMMQuestion'; Write-Output ('ANSWER'+$answer)\r"))
	collect("RMMQuestion")
	_ = s.Input([]byte("accepted\r"))
	collect("ANSWERaccepted")
	// A long command can be interrupted and the SAME process can accept input.
	_ = s.Input([]byte("Start-Sleep -Seconds 60\r"))
	time.Sleep(150 * time.Millisecond)
	_ = s.Input([]byte{3})
	time.Sleep(150 * time.Millisecond)
	_ = s.Input([]byte("Write-Output ('INTERRUPT'+(20+22))\r"))
	collect("INTERRUPT42")
	// Use direct process creation, not ShellExecute/profile machinery that is
	// unavailable to restricted service accounts and can invoke other OS brokers.
	_ = s.Input([]byte("$psi=New-Object Diagnostics.ProcessStartInfo; $psi.FileName=Join-Path $PSHOME powershell.exe; $psi.Arguments='-NoLogo -NoProfile -Command Start-Sleep -Seconds 60'; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $child=[Diagnostics.Process]::Start($psi)\r"))
	var info struct {
		TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime int64
		TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses     uint32
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		e = windows.QueryInformationJobObject(s.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
		if e != nil || info.ActiveProcesses >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if e != nil || info.ActiveProcesses < 2 {
		t.Fatal("descendant did not inherit job", e, info.ActiveProcesses)
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process termination blocked")
	}
	select {
	case <-s.processDone:
	default:
		t.Fatal("PowerShell survived close")
	}
	select {
	case <-s.readDone:
	default:
		t.Fatal("ConPTY reader survived close")
	}
}
