package desktop

import (
	"bytes"
	"context"
	"golang.org/x/sys/windows"
	"image/jpeg"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestNativeLayoutsAndCompleteInputTaps(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("Windows x64")
	}
	if unsafe.Sizeof(nativeInput{}) != 40 || unsafe.Sizeof(mouseInput{}) != 32 || unsafe.Sizeof(keyboardInput{}) != 24 || unsafe.Sizeof(bitmapHeader{}) != 40 || unsafe.Sizeof(windowClass{}) != 80 || unsafe.Sizeof(windowMessage{}) != 48 {
		t.Fatal("Windows ABI mismatch")
	}
	for _, v := range []Input{{Kind: "key", Key: 13, Ctrl: true, Shift: true}, {Kind: "text", Text: "A😀"}, {Kind: "click", Button: 1}, {Kind: "double-click", Button: 3}, {Kind: "wheel", Button: -1}, {Kind: "move", X: 123, Y: 456}} {
		if !v.Valid() {
			t.Fatal(v)
		}
		n := nativeEvents(v)
		if len(n) == 0 {
			t.Fatal("no events")
		}
		var held int
		for _, e := range n {
			if e.Type == 1 {
				k := (*keyboardInput)(unsafe.Pointer(&e.Data[0]))
				if k.Flags&2 == 0 {
					held++
				} else {
					held--
				}
			}
		}
		if held != 0 {
			t.Fatal("incomplete key chord")
		}
	}
}

// This test creates a private off-screen bitmap. It neither captures the user's
// monitor nor sends input to their applications.
func TestCaptureOwnedOffscreenBitmap(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, _, _ := createDC.Call(0)
	if source == 0 {
		t.Fatal("memory DC unavailable")
	}
	defer deleteDC.Call(source)
	const w, h = 2560, 1440
	bmi := struct {
		Header bitmapHeader
		Color  uint32
	}{Header: bitmapHeader{Size: 40, Width: w, Height: -h, Planes: 1, BitCount: 32}}
	var pixels unsafe.Pointer
	bmp, _, _ := createDIB.Call(source, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bmp == 0 || pixels == nil {
		t.Fatal("private DIB unavailable")
	}
	defer deleteObject.Call(bmp)
	old, _, _ := selectObject.Call(source, bmp)
	defer selectObject.Call(source, old)
	raw := unsafe.Slice((*byte)(pixels), w*h*4)
	for i := 0; i < len(raw); i += 4 {
		raw[i] = 32
		raw[i+1] = 64
		raw[i+2] = 192
		raw[i+3] = 255
	}
	b, e := captureDC(source, w, h)
	if e != nil {
		t.Fatal(e)
	}
	if !FrameValid(b) {
		t.Fatal("frame bounds")
	}
	img, e := jpeg.Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	if img.Bounds().Dx() != 1280 || img.Bounds().Dy() != 720 {
		t.Fatal(img.Bounds())
	}
	r, g, bl, _ := img.At(50, 50).RGBA()
	if r < 180*256 || g < 50*256 || g > 80*256 || bl > 50*256 {
		t.Fatal("incorrect BGRA conversion", r, g, bl)
	}
}

// A request starts the session without
// a consent prompt, but a stopped session can never be resumed or replayed.
func TestCompanionStartsWithoutConsentButNeverReplays(t *testing.T) {
	m := &companionModel{}
	q := Request{ID: testPeer, Actor: "technician", Expires: time.Now().Add(15 * time.Minute).Unix(), Control: true}
	if e := m.update(Reply{Request: &q}); e != nil {
		t.Fatal(e)
	}
	if p := m.snapshot(); p.State != "active" {
		t.Fatal("session did not start without a prompt", p.State)
	}
	m.stop("ended")
	if p := m.snapshot(); p.State != "ended" {
		t.Fatal("stop")
	}
	_ = m.update(Reply{})
	if e := m.update(Reply{Request: &q}); e == nil {
		t.Fatal("consent replayed")
	}
	q.ID = testDevice
	if e := m.update(Reply{Request: &q, Inputs: []Input{{Kind: "key", Key: 13}}}); e == nil {
		t.Fatal("input with a new request")
	}
}

// Explicit local diagnostic only: no consent, capture or input is generated.
func TestInstalledDesktopPipe(t *testing.T) {
	if os.Getenv("OPENRMM_TEST_INSTALLED_DESKTOP") != "1" {
		t.Skip("opt-in installed-service IPC diagnostic")
	}
	if !ordinaryUser() {
		t.Fatal("diagnostic requires the non-elevated active console user")
	}
	h, e := agentPipe()
	if e != nil {
		t.Fatal("cannot authenticate installed agent pipe", e)
	}
	defer windows.CloseHandle(h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e = pipeWrite(ctx, h, Exchange{}); e != nil {
		t.Fatal(e)
	}
	var r Reply
	if e = pipeRead(ctx, h, &r); e != nil {
		t.Fatal(e)
	}
	if r.Request != nil || len(r.Inputs) > 0 {
		t.Fatal("diagnostic found an unexpected session; consent was not granted")
	}
	// An orphaned synthetic frame is discarded by the hub; this checks the
	// maximum local-pipe -> restricted agent -> real HTTPS relay path without
	// sharing a monitor or creating/activating an administrator session.
	frame := make([]byte, MaxFrame)
	copy(frame, testJPEG(t))
	if e = pipeWrite(ctx, h, Exchange{ID: testDevice, State: "active", Frame: frame}); e != nil {
		t.Fatal("maximum private frame write", e)
	}
	if e = pipeRead(ctx, h, &r); e != nil {
		t.Fatal("maximum private frame relay", e)
	}
	if r.Request != nil || len(r.Inputs) > 0 {
		t.Fatal("unexpected real session; diagnostic did not consent")
	}
}
