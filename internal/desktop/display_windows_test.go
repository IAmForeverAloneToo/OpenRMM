package desktop

import (
	"bytes"
	"image/jpeg"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestLocalDisplayChoicesAndLayoutChecksWithoutCapture(t *testing.T) {
	if unsafe.Sizeof(monitorInfo{}) != 40 {
		t.Fatal("MONITORINFO ABI")
	}
	if !consoleUser() {
		t.Skip("interactive console metadata")
	}
	enableDPI()
	items, virtual, e := displayLayout()
	if e != nil {
		t.Fatal(e)
	}
	s, ok := selectionFor(items, virtual, 0, "balanced")
	if !ok || !s.current() {
		t.Fatal("current display selection rejected")
	}
	if _, ok = selectionFor(items, virtual, len(items), "balanced"); ok {
		t.Fatal("display outside the layout accepted")
	}
	if d := reported(items); len(d) != len(items) || !DisplaysValid(d) || !d[0].Primary {
		t.Fatal("reported layout", d)
	}
	// The dashboard chooses display and quality and may change them during
	// the session; identity fields may not change.
	m := &companionModel{}
	q := Request{ID: testPeer, Actor: "test", Control: true, Expires: time.Now().Add(time.Minute).Unix()}
	if e = m.update(Reply{Request: &q}); e != nil {
		t.Fatal(e)
	}
	if d, quality := m.choice(); d != 0 || quality != "balanced" {
		t.Fatal("default choice", d, quality)
	}
	q.Quality = "bandwidth"
	if e = m.update(Reply{Request: &q}); e != nil {
		t.Fatal(e)
	}
	if _, quality := m.choice(); quality != "bandwidth" {
		t.Fatal("quality change ignored")
	}
	q.Actor = "someone else"
	if e = m.update(Reply{Request: &q}); e == nil {
		t.Fatal("identity change accepted")
	}
	q.Actor, q.Quality = "test", "arbitrary"
	if validRequest(q) {
		t.Fatal("unknown quality accepted")
	}
	s.Virtual.Right++
	if s.current() {
		t.Fatal("layout changes silently accepted")
	}
}

// All pixels belong to a private off-screen bitmap, never a user's display.
func TestSelectedRegionAndQualityProfilesOnOwnedBitmap(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	source, _, _ := createDC.Call(0)
	if source == 0 {
		t.Fatal("memory DC")
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
		t.Fatal("private bitmap")
	}
	defer deleteObject.Call(bmp)
	old, _, _ := selectObject.Call(source, bmp)
	defer selectObject.Call(source, old)
	raw := unsafe.Slice((*byte)(pixels), w*h*4)
	for y := range h {
		for x := range w {
			i := (y*w + x) * 4
			raw[i+3] = 255
			if x < w/2 {
				raw[i+2] = 220
			} else {
				raw[i] = 220
			}
		}
	}
	for name, size := range map[string][2]int{"bandwidth": {960, 540}, "balanced": {1280, 720}, "detail": {1280, 720}} {
		b, e := captureRegionDC(source, region{0, 0, w, h}, name)
		if e != nil || !FrameValid(b) {
			t.Fatal(name, e)
		}
		img, e := jpeg.Decode(bytes.NewReader(b))
		if e != nil || img.Bounds().Dx() != size[0] || img.Bounds().Dy() != size[1] {
			t.Fatal("profile dimensions", name, e)
		}
	}
	b, e := captureRegionDC(source, region{w / 2, 0, w, h}, "detail")
	if e != nil {
		t.Fatal(e)
	}
	img, e := jpeg.Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r, _, blue, _ := img.At(10, 10).RGBA()
	if r > 40*256 || blue < 180*256 {
		t.Fatal("captured pixels outside selected region")
	}
	if _, e = captureRegionDC(source, region{0, 0, w, h}, "arbitrary"); e == nil {
		t.Fatal("invalid profile")
	}
}
