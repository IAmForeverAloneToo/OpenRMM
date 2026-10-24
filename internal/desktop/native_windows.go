package desktop

import (
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"runtime"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var openInputDesktop = user32.NewProc("OpenInputDesktop")
var closeDesktop = user32.NewProc("CloseDesktop")
var getThreadDesktop = user32.NewProc("GetThreadDesktop")
var getObjectInfo = user32.NewProc("GetUserObjectInformationW")
var getMetrics = user32.NewProc("GetSystemMetrics")
var getDC = user32.NewProc("GetDC")
var releaseDC = user32.NewProc("ReleaseDC")
var createDC = gdi32.NewProc("CreateCompatibleDC")
var deleteDC = gdi32.NewProc("DeleteDC")
var createDIB = gdi32.NewProc("CreateDIBSection")
var selectObject = gdi32.NewProc("SelectObject")
var deleteObject = gdi32.NewProc("DeleteObject")
var stretchBlt = gdi32.NewProc("StretchBlt")
var sendInput = user32.NewProc("SendInput")
var getAsyncKeyState = user32.NewProc("GetAsyncKeyState")
var setDPI = user32.NewProc("SetProcessDpiAwarenessContext")
var setDPIAware = user32.NewProc("SetProcessDPIAware")

type bitmapHeader struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPels, YPels           int32
	Used, Important        uint32
}

func objectName(h uintptr) string {
	var b [64]uint16
	var n uint32
	r, _, _ := getObjectInfo.Call(h, 2, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Sizeof(b)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || n > uint32(unsafe.Sizeof(b)) {
		return ""
	}
	return windows.UTF16ToString(b[:])
}
func consoleUser() bool {
	var sid uint32
	return windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid) == nil && sid != 0 && sid != 0xffffffff && sid == windows.WTSGetActiveConsoleSessionId()
}
func usableDesktop() bool {
	if !consoleUser() {
		return false
	}
	h, _, _ := openInputDesktop.Call(0, 0, 1)
	if h == 0 {
		return false
	}
	defer closeDesktop.Call(h)
	t, _, _ := getThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	return objectName(h) == "Default" && objectName(t) == "Default"
}
func ordinaryUser() bool {
	t := windows.GetCurrentProcessToken()
	var b [256]byte
	var n uint32
	if windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &b[0], uint32(len(b)), &n) != nil {
		return false
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&b[0]))
	if label.Label.Sid == nil || !label.Label.Sid.IsValid() {
		return false
	}
	s := label.Label.Sid
	if s.SubAuthorityCount() == 0 {
		return false
	}
	rid := s.SubAuthority(uint32(s.SubAuthorityCount() - 1))
	return rid >= 0x2000 && rid < 0x3000 && !t.IsElevated() && consoleUser()
}
func enableDPI() {
	if setDPI.Find() == nil {
		r, _, _ := setDPI.Call(^uintptr(3))
		if r != 0 {
			return
		}
	}
	_, _, _ = setDPIAware.Call()
}

// captureDC is independently testable against an owned off-screen GDI surface.
// source must be a DC the caller owns; no window handles or coordinates arrive
// from the remote browser. The old entry point keeps balanced primary coverage.
func captureDC(source uintptr, sw, sh int) ([]byte, error) {
	return captureRegionDC(source, region{0, 0, sw, sh}, "balanced")
}
func captureRegionDC(source uintptr, bounds region, name string) ([]byte, error) {
	p, ok := profile(name)
	if !ok || !bounds.valid() {
		return nil, ErrUnavailable
	}
	sw, sh := bounds.Right-bounds.Left, bounds.Bottom-bounds.Top
	if sw < 1 || sh < 1 || sw > 32768 || sh > 32768 {
		return nil, ErrUnavailable
	}
	w, h := sw, sh
	if w > p.Width {
		h = h * p.Width / w
		w = p.Width
	}
	if h > p.Height {
		w = w * p.Height / h
		h = p.Height
	}
	if w < 1 || h < 1 {
		return nil, ErrUnavailable
	}
	dc, _, _ := createDC.Call(source)
	if dc == 0 {
		return nil, ErrUnavailable
	}
	defer deleteDC.Call(dc)
	bmi := struct {
		Header bitmapHeader
		Color  uint32
	}{Header: bitmapHeader{Size: 40, Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}}
	var pixels unsafe.Pointer
	bitmap, _, _ := createDIB.Call(source, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&pixels)), 0, 0)
	if bitmap == 0 || pixels == nil {
		return nil, ErrUnavailable
	}
	defer deleteObject.Call(bitmap)
	old, _, _ := selectObject.Call(dc, bitmap)
	if old == 0 || old == ^uintptr(0) {
		return nil, ErrUnavailable
	}
	defer selectObject.Call(dc, old)
	r, _, _ := stretchBlt.Call(dc, 0, 0, uintptr(w), uintptr(h), source, uintptr(bounds.Left), uintptr(bounds.Top), uintptr(sw), uintptr(sh), 0x40cc0020)
	if r == 0 {
		return nil, ErrUnavailable
	}
	// GDI batch writes must finish before Go reads the DIB's memory.
	_, _, _ = gdi32.NewProc("GdiFlush").Call()
	raw := unsafe.Slice((*byte)(pixels), w*h*4)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(raw); i += 4 {
		img.Pix[i] = raw[i+2]
		img.Pix[i+1] = raw[i+1]
		img.Pix[i+2] = raw[i]
		img.Pix[i+3] = 255
	}
	var out bytes.Buffer
	if e := jpeg.Encode(&out, img, &jpeg.Options{Quality: p.Quality}); e != nil {
		return nil, e
	}
	if out.Len() > MaxFrame {
		out.Reset()
		if e := jpeg.Encode(&out, img, &jpeg.Options{Quality: 40}); e != nil || out.Len() > MaxFrame {
			return nil, ErrUnavailable
		}
	}
	return out.Bytes(), nil
}
func Capture() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !usableDesktop() {
		return nil, ErrUnavailable
	}
	w, _, _ := getMetrics.Call(0)
	h, _, _ := getMetrics.Call(1)
	dc, _, _ := getDC.Call(0)
	if dc == 0 {
		return nil, ErrUnavailable
	}
	defer releaseDC.Call(0, dc)
	b, e := captureDC(dc, int(w), int(h))
	if !usableDesktop() {
		return nil, ErrUnavailable
	}
	return b, e
}

// INPUT's x64 union begins at offset 8 and is 32 bytes. Using explicit widths
// avoids Go's different alignment for the anonymous C union.
type nativeInput struct {
	Type uint32
	Pad  uint32
	Data [32]byte
}
type mouseInput struct {
	X, Y              int32
	Data, Flags, Time uint32
	Pad               uint32
	Extra             uintptr
}
type keyboardInput struct {
	Key, Scan   uint16
	Flags, Time uint32
	Pad         uint32
	Extra       uintptr
}

func keyboard(k, scan uint16, flags uint32) nativeInput {
	v := nativeInput{Type: 1}
	*(*keyboardInput)(unsafe.Pointer(&v.Data[0])) = keyboardInput{Key: k, Scan: scan, Flags: flags}
	return v
}
func mouse(x, y int, data, flags uint32) nativeInput {
	v := nativeInput{}
	*(*mouseInput)(unsafe.Pointer(&v.Data[0])) = mouseInput{X: int32(x), Y: int32(y), Data: data, Flags: flags}
	return v
}
func keyTap(events []nativeInput, k uint16) []nativeInput {
	f := uint32(0)
	if k >= 33 && k <= 46 {
		f = 1
	}
	return append(events, keyboard(k, 0, f), keyboard(k, 0, f|2))
}
func nativeEvents(v Input) []nativeInput {
	var events []nativeInput
	switch v.Kind {
	case "move", "click", "double-click", "wheel":
		events = append(events, mouse(v.X, v.Y, 0, 0x8001)) // normalized primary screen
		if v.Kind == "wheel" {
			data := int32(v.Button * 120)
			events = append(events, mouse(0, 0, uint32(data), 0x800))
		}
		if v.Kind == "click" || v.Kind == "double-click" {
			down, up := uint32(2), uint32(4)
			if v.Button == 2 {
				down, up = 32, 64
			}
			if v.Button == 3 {
				down, up = 8, 16
			}
			events = append(events, mouse(0, 0, 0, down), mouse(0, 0, 0, up))
			if v.Kind == "double-click" {
				events = append(events, mouse(0, 0, 0, down), mouse(0, 0, 0, up))
			}
		}
	case "text":
		for _, u := range utf16.Encode([]rune(v.Text)) {
			events = append(events, keyboard(0, u, 4), keyboard(0, u, 6))
		}
	case "key":
		if v.Ctrl {
			events = append(events, keyboard(17, 0, 0))
		}
		if v.Alt {
			events = append(events, keyboard(18, 0, 0))
		}
		if v.Shift {
			events = append(events, keyboard(16, 0, 0))
		}
		events = keyTap(events, v.Key)
		if v.Shift {
			events = append(events, keyboard(16, 0, 2))
		}
		if v.Alt {
			events = append(events, keyboard(18, 0, 2))
		}
		if v.Ctrl {
			events = append(events, keyboard(17, 0, 2))
		}
	}
	return events
}
func ApplyInput(v Input) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !v.Valid() {
		return ErrUnavailable
	}
	return insertNativeInput(v, nativeEvents(v))
}
func insertNativeInput(v Input, events []nativeInput) error {
	if !v.Valid() || !usableDesktop() {
		return ErrUnavailable
	}
	// Avoid borrowing or releasing modifiers/buttons held by the local user.
	for _, k := range []uint16{1, 2, 4, 16, 17, 18, 91, 92} {
		r, _, _ := getAsyncKeyState.Call(uintptr(k))
		if r&0x8000 != 0 {
			return nil
		}
	}
	if len(events) == 0 {
		return ErrInvalid
	}
	n, _, _ := sendInput.Call(uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])), unsafe.Sizeof(nativeInput{}))
	runtime.KeepAlive(events)
	if int(n) != len(events) {
		// If Windows accepted only a prefix, release this event's synthetic keys.
		var release []nativeInput
		for _, e := range events {
			if e.Type == 1 {
				ki := *(*keyboardInput)(unsafe.Pointer(&e.Data[0]))
				if ki.Flags&2 != 0 {
					release = append(release, e)
				}
			} else {
				mi := *(*mouseInput)(unsafe.Pointer(&e.Data[0]))
				if mi.Flags == 4 || mi.Flags == 16 || mi.Flags == 64 {
					release = append(release, e)
				}
			}
		}
		if len(release) > 0 {
			_, _, _ = sendInput.Call(uintptr(len(release)), uintptr(unsafe.Pointer(&release[0])), unsafe.Sizeof(nativeInput{}))
			runtime.KeepAlive(release)
		}
		return errors.New("Windows did not accept remote input")
	}
	return nil
}
