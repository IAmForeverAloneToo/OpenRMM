package desktop

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type monitor struct {
	Handle  uintptr
	Bounds  region
	Primary bool
}
type displaySelection struct {
	Monitor monitor
	Layout  []monitor
	Virtual region
	Profile string
}
type monitorInfo struct {
	Size         uint32
	Bounds, Work struct{ Left, Top, Right, Bottom int32 }
	Flags        uint32
}
type monitorEnumeration struct {
	Items  []monitor
	Failed bool
}

var enumMonitors = user32.NewProc("EnumDisplayMonitors")
var getMonitorInfo = user32.NewProc("GetMonitorInfoW")
var enumerationSerial sync.Mutex
var enumerationStateMu sync.Mutex
var enumerationState *monitorEnumeration

// Allocate one callback for the lifetime of the process. NewCallback allocations
// cannot be freed, so never allocate callbacks in the capture/input polling loop.
var monitorCallback = windows.NewCallback(func(handle, dc, rect, data uintptr) uintptr {
	enumerationStateMu.Lock()
	defer enumerationStateMu.Unlock()
	state := enumerationState
	if state == nil {
		return 0
	}
	info := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	if ok, _, _ := getMonitorInfo.Call(handle, uintptr(unsafe.Pointer(&info))); ok == 0 {
		state.Failed = true
		return 0
	}
	r := region{int(info.Bounds.Left), int(info.Bounds.Top), int(info.Bounds.Right), int(info.Bounds.Bottom)}
	if !r.valid() || r.Right-r.Left > 32768 || r.Bottom-r.Top > 32768 {
		state.Failed = true
		return 0
	}
	for i, m := range state.Items {
		if m.Bounds == r {
			if info.Flags&1 != 0 {
				state.Items[i].Primary = true
				state.Items[i].Handle = handle
			}
			return 1
		}
	} // mirrored surfaces
	if len(state.Items) >= 16 {
		state.Failed = true
		return 0
	}
	state.Items = append(state.Items, monitor{handle, r, info.Flags&1 != 0})
	return 1
})

func displayLayout() ([]monitor, region, error) {
	// Serialize the synchronous callback without passing a Go object pointer
	// through Win32's integer LPARAM, including under checkptr instrumentation.
	enumerationSerial.Lock()
	defer enumerationSerial.Unlock()
	state := monitorEnumeration{}
	enumerationStateMu.Lock()
	enumerationState = &state
	enumerationStateMu.Unlock()
	ok, _, _ := enumMonitors.Call(0, 0, monitorCallback, 0)
	enumerationStateMu.Lock()
	enumerationState = nil
	enumerationStateMu.Unlock()
	metric := func(n uintptr) int { v, _, _ := getMetrics.Call(n); return int(int32(v)) }
	x, y, w, h := metric(76), metric(77), metric(78), metric(79)
	virtual := region{x, y, x + w, y + h}
	if ok == 0 || state.Failed || len(state.Items) == 0 || !virtual.valid() {
		return nil, region{}, ErrUnavailable
	}
	primary := 0
	for _, m := range state.Items {
		if !virtual.contains(m.Bounds) {
			return nil, region{}, ErrUnavailable
		}
		if m.Primary {
			primary++
		}
	}
	if primary != 1 {
		return nil, region{}, ErrUnavailable
	}
	sort.Slice(state.Items, func(i, j int) bool {
		a, b := state.Items[i], state.Items[j]
		if a.Primary != b.Primary {
			return a.Primary
		}
		if a.Bounds.Left != b.Bounds.Left {
			return a.Bounds.Left < b.Bounds.Left
		}
		if a.Bounds.Top != b.Bounds.Top {
			return a.Bounds.Top < b.Bounds.Top
		}
		return a.Handle < b.Handle
	})
	return state.Items, virtual, nil
}
func (s displaySelection) valid() bool {
	_, ok := profile(s.Profile)
	if !ok || len(s.Layout) < 1 || len(s.Layout) > 16 || !s.Virtual.contains(s.Monitor.Bounds) {
		return false
	}
	for _, m := range s.Layout {
		if m == s.Monitor {
			return true
		}
	}
	return false
}
func (s displaySelection) current() bool {
	if !s.valid() {
		return false
	}
	items, virtual, e := displayLayout()
	if e != nil || virtual != s.Virtual || len(items) != len(s.Layout) {
		return false
	}
	for i, m := range items {
		if m != s.Layout[i] {
			return false
		}
	}
	return true
}
func (m monitor) label() string {
	name := "Display"
	if m.Primary {
		name = "Primary display"
	}
	return fmt.Sprintf("%s: %d x %d at (%d, %d)", name, m.Bounds.Right-m.Bounds.Left, m.Bounds.Bottom-m.Bounds.Top, m.Bounds.Left, m.Bounds.Top)
}
func captureSelected(s displaySelection) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !usableDesktop() || !s.current() {
		return nil, ErrUnavailable
	}
	dc, _, _ := getDC.Call(0)
	if dc == 0 {
		return nil, ErrUnavailable
	}
	defer releaseDC.Call(0, dc)
	b, e := captureRegionDC(dc, s.Monitor.Bounds, s.Profile)
	if !usableDesktop() || !s.current() {
		return nil, ErrUnavailable
	}
	return b, e
}
func applySelected(v Input, s displaySelection) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !v.Valid() || !s.current() {
		return ErrUnavailable
	}
	events := nativeEvents(v)
	if v.Kind == "move" || v.Kind == "click" || v.Kind == "double-click" || v.Kind == "wheel" {
		x, y, e := displayPoint(v.X, v.Y, s.Monitor.Bounds, s.Virtual)
		if e != nil {
			return e
		}
		events[0] = mouse(x, y, 0, 0xc001) // MOVE | ABSOLUTE | VIRTUALDESK
	}
	if e := insertNativeInput(v, events); e != nil {
		return e
	}
	if !s.current() {
		return ErrUnavailable
	}
	return nil
}
