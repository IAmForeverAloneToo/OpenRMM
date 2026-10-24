package desktop

import (
	"context"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Opt-in only. All real input is guarded by ownership/foreground checks and
// observed by this temporary window. Never capture a monitor or type commands.
func TestNativeWindowInput(t *testing.T) {
	if os.Getenv("OPENRMM_TEST_DESKTOP_INPUT") != "1" {
		t.Skip("opt-in visible owned-window input diagnostic")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ordinaryUser() || !usableDesktop() {
		t.Fatal("requires the ordinary active console user")
	}
	enableDPI()
	monitors, virtual, e := displayLayout()
	if e != nil {
		t.Fatal(e)
	}
	selection := displaySelection{monitors[0], monitors, virtual, "balanced"}
	foreground := user32.NewProc("GetForegroundWindow")
	setForeground := user32.NewProc("SetForegroundWindow")
	setFocus := user32.NewProc("SetFocus")
	peek := user32.NewProc("PeekMessageW")
	getCursor := user32.NewProc("GetCursorPos")
	setCursor := user32.NewProc("SetCursorPos")
	previous, _, _ := foreground.Call()
	var cursor struct{ X, Y int32 }
	gotCursor, _, _ := getCursor.Call(uintptr(unsafe.Pointer(&cursor)))
	var chars []uint16
	var clicks, releases, wheels int
	var ctrlArrow bool
	proc := windows.NewCallback(func(hwnd uintptr, msg uint32, wp, lp uintptr) uintptr {
		switch msg {
		case 0x102:
			chars = append(chars, uint16(wp))
			return 0
		case 0x100:
			if wp == 37 {
				v, _, _ := user32.NewProc("GetKeyState").Call(17)
				ctrlArrow = v&0x8000 != 0
			}
			return 0
		case 0x201:
			clicks++
			return 0
		case 0x202:
			releases++
			return 0
		case 0x20a:
			wheels++
			return 0
		}
		r, _, _ := defWindowProc.Call(hwnd, uintptr(msg), wp, lp)
		return r
	})
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	name := textPointer("OpenRMM.Input.Test." + id)
	var instance windows.Handle
	if e = windows.GetModuleHandleEx(0, nil, &instance); e != nil {
		t.Fatal(e)
	}
	wc := windowClass{Size: uint32(unsafe.Sizeof(windowClass{})), Proc: proc, Instance: uintptr(instance), Name: name, Background: 16}
	wc.Cursor, _, _ = user32.NewProc("LoadCursorW").Call(0, 32512)
	if r, _, e := registerClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		t.Fatal(e)
	}
	defer user32.NewProc("UnregisterClassW").Call(uintptr(unsafe.Pointer(name)), uintptr(instance))
	title := textPointer("OpenRMM — isolated input verification")
	window, _, e := createWindow.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(title)), 0x00ca0000, 160, 160, 600, 320, 0, 0, uintptr(instance), 0)
	runtime.KeepAlive(wc)
	runtime.KeepAlive(title)
	if window == 0 {
		t.Fatal(e)
	}
	defer destroyWindow.Call(window)
	defer func() {
		if h, _, _ := foreground.Call(); h == window {
			if gotCursor != 0 {
				setCursor.Call(uintptr(cursor.X), uintptr(cursor.Y))
			}
			if previous != 0 {
				setForeground.Call(previous)
			}
		}
	}()
	label := child(window, "STATIC", "OpenRMM input test. If needed, click the title bar to focus.\r\nOnly generated text, a harmless key chord, click and wheel are tested.\r\nNo desktop image, clipboard, command or file is read.", 100, 20, 20, 540, 90)
	if label == 0 {
		t.Fatal("fixture label")
	}
	pump := func() {
		var msg windowMessage
		for {
			r, _, _ := peek.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
			if r == 0 {
				return
			}
			translateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			dispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}
	showWindow.Call(window, 1)
	showWindow.Call(window, 1)
	setForeground.Call(window)
	deadline := time.Now().Add(20 * time.Second)
	for {
		pump()
		h, _, _ := foreground.Call()
		if h == window {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture did not receive foreground; no input sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	setFocus.Call(window)
	var point struct{ X, Y int32 }
	point.X = 280
	point.Y = 180
	if r, _, e := user32.NewProc("ClientToScreen").Call(window, uintptr(unsafe.Pointer(&point))); r == 0 {
		t.Fatal(e)
	}
	w, _, _ := getMetrics.Call(0)
	h, _, _ := getMetrics.Call(1)
	if w < 2 || h < 2 || point.X < 0 || point.Y < 0 || int(point.X) >= int(w) || int(point.Y) >= int(h) {
		t.Fatal("fixture outside primary monitor; no input sent")
	}
	x, y := int(point.X)*65535/(int(w)-1), int(point.Y)*65535/(int(h)-1)
	hub, _, _, _ := testHub(t)
	q := start(t, hub, true)
	m := &companionModel{}
	if e = m.update(Reply{Request: &q}); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e = hub.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active", Frame: testJPEG(t)}); e != nil {
		t.Fatal(e)
	}
	text := "RMM ✓😀"
	input := []Input{{Kind: "click", Button: 1, X: x, Y: y}, {Kind: "text", Text: text}, {Kind: "key", Key: 37, Ctrl: true}, {Kind: "wheel", Button: 1, X: x, Y: y}}
	if e = hub.Input(ctx, q.ID, "owner", Batch{Sequence: 1, Events: input}); e != nil {
		t.Fatal(e)
	}
	r, e := hub.Exchange(ctx, testDevice, Exchange{Ready: true, Peer: testPeer, ID: q.ID, State: "active"})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.update(r); e != nil {
		t.Fatal(e)
	}
	var inputError error
	m.applyInputs(r, func(v Input) error {
		active, _, _ := foreground.Call()
		var pid uint32
		user32.NewProc("GetWindowThreadProcessId").Call(active, uintptr(unsafe.Pointer(&pid)))
		if active != window || pid != windows.GetCurrentProcessId() {
			inputError = ErrUnavailable
			return inputError
		}
		if v.Kind == "click" || v.Kind == "wheel" {
			packed := uintptr(uint32(point.X)) | uintptr(uint32(point.Y))<<32
			target, _, _ := user32.NewProc("WindowFromPoint").Call(packed)
			if target != window {
				inputError = ErrUnavailable
				return inputError
			}
		}
		inputError = applySelected(v, selection)
		until := time.Now().Add(80 * time.Millisecond)
		for time.Now().Before(until) {
			pump()
			time.Sleep(time.Millisecond)
		}
		return inputError
	})
	if inputError != nil {
		t.Fatal("fixture lost input permission/focus", inputError)
	}
	pump()
	if !reflect.DeepEqual(chars, utf16.Encode([]rune(text))) || clicks != 1 || releases != 1 || wheels != 1 || !ctrlArrow {
		t.Fatalf("native delivery mismatch: text_match=%t char_count=%d clicks=%d releases=%d wheels=%d ctrlArrow=%v", reflect.DeepEqual(chars, utf16.Encode([]rune(text))), len(chars), clicks, releases, wheels, ctrlArrow)
	}
	if e = hub.Stop(ctx, q.ID, "owner"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = hub.View(ctx, q.ID, "owner"); e == nil {
		t.Fatal("fixture session survived stop")
	}
}
