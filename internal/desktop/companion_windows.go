package desktop

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

// Window helpers, used by the native input tests' own test windows. The
// companion itself has no window.
var createWindow = user32.NewProc("CreateWindowExW")
var defWindowProc = user32.NewProc("DefWindowProcW")
var destroyWindow = user32.NewProc("DestroyWindow")
var setWindowText = user32.NewProc("SetWindowTextW")
var postMessage = user32.NewProc("PostMessageW")
var getMessage = user32.NewProc("GetMessageW")
var translateMessage = user32.NewProc("TranslateMessage")
var dispatchMessage = user32.NewProc("DispatchMessageW")
var postQuit = user32.NewProc("PostQuitMessage")
var registerClass = user32.NewProc("RegisterClassExW")
var showWindow = user32.NewProc("ShowWindow")
var setForeground = user32.NewProc("SetForegroundWindow")
var setTimer = user32.NewProc("SetTimer")

type windowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}
type windowMessage struct {
	Window         uintptr
	Message        uint32
	Pad            uint32
	WParam, LParam uintptr
	Time           uint32
	X, Y           int32
	Private        uint32
}

func textPointer(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }
func setText(h uintptr, s string) {
	p := textPointer(s)
	_, _, _ = setWindowText.Call(h, uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
}
func child(parent uintptr, class, text string, id, x, y, w, h int) uintptr {
	c, t := textPointer(class), textPointer(text)
	style := uintptr(0x50000000)
	if class == "BUTTON" {
		style |= 0x10000
	}
	r, _, _ := createWindow.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(t)), style, uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, uintptr(id), 0, 0)
	runtime.KeepAlive(c)
	runtime.KeepAlive(t)
	return r
}

// companionModel is the companion's view of the current session. The
// display and quality come from the session request (chosen in the
// dashboard) and may change while it runs.
type companionModel struct {
	mu      sync.Mutex
	request *Request
	state   string
	lastID  string
	seen    time.Time
}

func (m *companionModel) update(r Reply) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Request == nil {
		m.request = nil
		m.state = ""
		return nil
	}
	q := *r.Request
	if !validRequest(q) || len(r.Inputs) > 64 {
		return ErrInvalid
	}
	for _, v := range r.Inputs {
		if !v.Valid() || !q.Control {
			return ErrInvalid
		}
	}
	if m.request != nil && m.request.ID == q.ID {
		if m.request.Actor != q.Actor || m.request.Control != q.Control || m.request.Expires != q.Expires {
			return ErrInvalid
		}
		// The dashboard may switch display or quality during the session.
		m.request.Display, m.request.Quality = q.Display, q.Quality
		return nil
	}
	if len(r.Inputs) > 0 {
		return ErrInvalid
	}
	if q.ID == m.lastID {
		return ErrInvalid
	}
	m.request = &q
	// Sessions start without asking and nothing is shown on the device.
	m.state = "active"
	m.seen = time.Now()
	return nil
}
func validRequest(q Request) bool {
	return len(q.Actor) > 0 && len(q.Actor) <= 128 && utf8.ValidString(q.Actor) && !strings.ContainsAny(q.Actor, "\x00\r\n") && protocol.ValidID(q.ID) && q.Expires > time.Now().Unix() && q.Expires <= time.Now().Add(16*time.Minute).Unix() && q.Display >= 0 && q.Display < 16 && ValidQuality(q.Quality)
}
func (m *companionModel) stop(state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.request != nil {
		m.state = state
		m.lastID = m.request.ID
	}
}

// choice is the current session's display index and quality profile.
func (m *companionModel) choice() (int, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.request == nil {
		return 0, "balanced"
	}
	q := m.request.Quality
	if q == "" {
		q = "balanced"
	}
	return m.request.Display, q
}

// selectionFor maps a session's display index onto the current layout.
func selectionFor(monitors []monitor, virtual region, display int, quality string) (displaySelection, bool) {
	if display < 0 || display >= len(monitors) {
		return displaySelection{}, false
	}
	s := displaySelection{monitors[display], monitors, virtual, quality}
	return s, s.valid()
}

// reported describes the layout for the dashboard, in the companion's order
// (primary first).
func reported(monitors []monitor) []Display {
	out := make([]Display, 0, len(monitors))
	for i, m := range monitors {
		out = append(out, Display{Index: i, Left: m.Bounds.Left, Top: m.Bounds.Top, Width: m.Bounds.Right - m.Bounds.Left, Height: m.Bounds.Bottom - m.Bounds.Top, Primary: m.Primary})
	}
	return out
}

// Recheck the local session for every event, including replies received after Stop
// or expiry. Keep the decision and one complete native tap under the same lock.
func (m *companionModel) applyInputs(r Reply, apply func(Input) error) {
	for _, v := range r.Inputs {
		m.mu.Lock()
		if m.request == nil || m.state != "active" || !m.request.Control || r.Request == nil || m.request.ID != r.Request.ID {
			m.mu.Unlock()
			return
		}
		if time.Now().Unix() >= m.request.Expires || time.Since(m.seen) >= 15*time.Minute {
			m.state = "ended"
			m.lastID = m.request.ID
			m.mu.Unlock()
			return
		}
		if !v.Valid() || apply(v) != nil {
			m.state = "unavailable"
			m.lastID = m.request.ID
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
	}
}
func (m *companionModel) snapshot() Exchange {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := Exchange{}
	if m.request != nil {
		if time.Now().Unix() >= m.request.Expires || time.Since(m.seen) >= 15*time.Minute {
			m.state = "ended"
			m.lastID = m.request.ID
		}
		p.ID = m.request.ID
		p.State = m.state
	}
	return p
}
func companionLoop(ctx context.Context, m *companionModel) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h, e := agentPipe()
	if e != nil {
		return
	}
	defer windows.CloseHandle(h)
	defer func() {
		m.mu.Lock()
		m.request = nil
		m.state = ""
		m.mu.Unlock()
	}()
	for ctx.Err() == nil {
		// The layout is read every round, so display changes are reported and
		// a session follows them.
		monitors, virtual, layoutErr := displayLayout()
		p := m.snapshot()
		display, quality := m.choice()
		selection, ok := selectionFor(monitors, virtual, display, quality)
		if p.ID != "" && p.State == "active" && (layoutErr != nil || !ok || !usableDesktop()) {
			m.stop("unavailable")
			p = m.snapshot()
		}
		if p.State == "active" {
			p.Frame, e = captureSelected(selection)
			if e != nil {
				m.stop("unavailable")
				p = m.snapshot()
			}
			// A stop may have arrived during capture. Never upload that frame.
			now := m.snapshot()
			if now.State != "active" || now.ID != p.ID {
				p = now
			}
		}
		if layoutErr == nil {
			p.Displays = reported(monitors)
		}
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = pipeWrite(c, h, p)
		var r Reply
		if e == nil {
			e = pipeRead(c, h, &r)
		}
		cancel()
		if e != nil {
			return
		}
		if e = m.update(r); e != nil {
			return
		}
		// Inputs go to the display the reply names.
		if r.Request != nil {
			if s, ok := selectionFor(monitors, virtual, r.Request.Display, quality); ok {
				m.applyInputs(r, func(v Input) error { return applySelected(v, s) })
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// RunCompanion runs the hidden desktop companion: no window, taskbar or tray
// icon. It connects to the installed agent and
// shares the display the dashboard chooses while a session runs.
func RunCompanion(ctx context.Context) error {
	if unsafe.Sizeof(uintptr(0)) != 8 || !ordinaryUser() {
		return fmt.Errorf("launch the desktop companion as the non-elevated user at the physical Windows console")
	}
	enableDPI()
	if _, _, e := displayLayout(); e != nil {
		return fmt.Errorf("cannot enumerate the active console displays")
	}
	// Reconnect until stopped: at sign-in the agent service (delayed start) may
	// not be running yet, and it restarts during updates.
	for ctx.Err() == nil {
		companionLoop(ctx, &companionModel{})
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}
