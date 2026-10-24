package windowsupdate

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestNativeAutomationABIAndLocalObjects(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("x64 adapter")
	}
	if unsafe.Sizeof(variant{}) != 24 || unsafe.Sizeof(params{}) != 24 {
		t.Fatal("incorrect Automation ABI")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r, _, _ := coInit.Call(0, 2)
	checkHR(r)
	defer coUninit.Call()
	a := &apartment{}
	defer a.close()
	i := a.create("Microsoft.Update.SystemInfo")
	_ = i.yes("RebootRequired")
	s := a.create("Microsoft.Update.Session")
	s.set("ClientApplicationID", "OpenRMM native binding test")
	search := a.child(s, "CreateUpdateSearcher")
	search.set("ServerSelection", 0)
	search.set("CanAutomaticallyUpgradeService", false)
	if search.num("ServerSelection") != 0 {
		t.Fatal("configured update source changed")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		installer := a.child(s, "CreateUpdateInstaller")
		installer.set("AllowSourcePrompts", false)
		installer.set("ForceQuiet", true)
		if installer.yes("AllowSourcePrompts") || !installer.yes("ForceQuiet") {
			t.Fatal("unattended installer flags")
		}

	}
	c := a.create("Microsoft.Update.UpdateColl")
	if c.num("Count") != 0 {
		t.Fatal("new collection not empty")
	}
	v := arg("Automation string ownership")
	if v.text(100) != "Automation string ownership" {
		t.Fatal("BSTR conversion")
	}
	v.clear()
}

func TestNativeClosedWindowRejectsBeforeCOMOrRestart(t *testing.T) {
	for _, action := range []string{"scan", "install", "restart"} {
		q := testJob(action)
		q.WindowStart = time.Now().Add(-2 * time.Hour).Unix()
		q.WindowEnd = q.WindowStart + 3600
		q.ExpiresAt = q.WindowEnd
		if action == "install" {
			q.ScanID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			q.Updates = []protocol.UpdateIdentity{testIdentity}
		}
		var result protocol.UpdateProgress
		NativeRun(context.Background(), q, func(p protocol.UpdateProgress) error { result = p; return nil })
		if result.Outcome != "blocked" || result.RebootKnown || !Terminal(result) {
			t.Fatal("closed window touched Windows", action, result)
		}
	}
}
