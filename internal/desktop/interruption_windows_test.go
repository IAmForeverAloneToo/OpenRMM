package desktop

import (
	"runtime"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestLocalStopRejectsLateAndMisboundInput(t *testing.T) {
	for _, mode := range []string{"stopped", "view", "other-session", "expired", "monotonic-expired"} {
		t.Run(mode, func(t *testing.T) {
			q := Request{ID: testDevice, Actor: "test", Control: mode != "view", Expires: time.Now().Add(15 * time.Minute).Unix()}
			m := &companionModel{}
			if e := m.update(Reply{Request: &q}); e != nil {
				t.Fatal(e)
			}
			r := Reply{Request: &q, Inputs: []Input{{Kind: "text", Text: "not sent"}}}
			switch mode {
			case "stopped":
				m.stop("ended")
			case "other-session":
				other := q
				other.ID = testPeer
				r.Request = &other
			case "expired":
				m.request.Expires = time.Now().Add(-time.Second).Unix()
			case "monotonic-expired":
				m.seen = time.Now().Add(-16 * time.Minute)
			}
			called := 0
			m.applyInputs(r, func(Input) error { called++; return nil })
			if called != 0 {
				t.Fatal("local authorization allowed late input", mode)
			}
		})
	}
}

func TestNativeInputFailureEndsSession(t *testing.T) {
	q := Request{ID: testDevice, Actor: "test", Control: true, Expires: time.Now().Add(15 * time.Minute).Unix()}
	m := &companionModel{}
	if e := m.update(Reply{Request: &q}); e != nil {
		t.Fatal(e)
	}
	r := Reply{Request: &q, Inputs: []Input{{Kind: "key", Key: 13}, {Kind: "key", Key: 13}}}
	called := 0
	m.applyInputs(r, func(Input) error { called++; return ErrUnavailable })
	if called != 1 || m.snapshot().State != "unavailable" {
		t.Fatal("continued after native desktop/input rejection")
	}
	m.applyInputs(r, func(Input) error { t.Fatal("reused a failed session"); return nil })
	_ = m.update(Reply{})
	if e := m.update(Reply{Request: &q}); e == nil {
		t.Fatal("resumed interrupted session")
	}
}

// This desktop is never made visible: SwitchDesktop is intentionally not used.
// Only the locked test thread moves; production Capture/ApplyInput must reject it.
func TestPrivateDesktopRejectsCaptureAndInput(t *testing.T) {
	if !consoleUser() {
		t.Skip("requires an interactive test process")
	}
	runtime.LockOSThread()
	// Leave this goroutine locked if restoration fails; Go then destroys its OS
	// thread instead of lending the altered desktop to unrelated goroutines.
	restored := false
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	old, _, _ := getThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	name := textPointer("OpenRMM-Test-" + id)
	h, _, e := user32.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(name)), 0, 0, 0, 0x83, 0)
	runtime.KeepAlive(name)
	if h == 0 {
		restored = true
		t.Fatalf("private desktop creation: %v", e)
	}
	defer closeDesktop.Call(h)
	set := user32.NewProc("SetThreadDesktop")
	defer func() {
		r, _, e := set.Call(old)
		if r == 0 {
			t.Errorf("test desktop restoration: %v", e)
		} else {
			restored = true
		}
	}()
	if r, _, e := set.Call(h); r == 0 {
		t.Fatalf("private thread desktop: %v", e)
	}
	if usableDesktop() {
		t.Fatal("non-input desktop accepted")
	}
	if b, e := Capture(); e == nil || len(b) != 0 {
		t.Fatal("captured a rejected desktop")
	}
	if e := ApplyInput(Input{Kind: "text", Text: "not sent"}); e == nil {
		t.Fatal("input accepted on rejected desktop")
	}
}
