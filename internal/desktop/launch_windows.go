package desktop

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The companion starts at every sign-in from the machine's Run key. An
// install or update of the agent stops it, and until the next sign-in remote
// desktop is unavailable; so the installed SYSTEM agent starts it in every
// active signed-in session that has none, at most once every five minutes
// per session.

const companionCheck = 30 * time.Second
const companionRetry = 5 * time.Minute

// EnsureCompanions runs until ctx ends. exe is the installed companion.
func EnsureCompanions(ctx context.Context, exe string, logger *slog.Logger) {
	if _, e := os.Stat(exe); e != nil {
		return
	}
	last := map[uint32]time.Time{}
	for {
		for _, session := range sessionsWithoutCompanion(exe) {
			if time.Since(last[session]) < companionRetry {
				continue
			}
			last[session] = time.Now()
			if e := startCompanion(session, exe); e != nil {
				logger.Warn("desktop companion could not be started in a signed-in session", "session", session)
			} else {
				logger.Info("desktop companion started in a signed-in session", "session", session)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(companionCheck):
		}
	}
}

// sessionsWithoutCompanion lists active user sessions (not session 0) in
// which the installed companion is not running.
func sessionsWithoutCompanion(exe string) []uint32 {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &count) != nil {
		return nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	active := map[uint32]bool{}
	for _, s := range unsafe.Slice(info, count) {
		if s.State == windows.WTSActive && s.SessionID != 0 {
			active[s.SessionID] = true
		}
	}
	if len(active) == 0 {
		return nil
	}
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snap, &p); e == nil; e = windows.Process32Next(snap, &p) {
		if !strings.EqualFold(windows.UTF16ToString(p.ExeFile[:]), filepath.Base(exe)) {
			continue
		}
		var session uint32
		if windows.ProcessIdToSessionId(p.ProcessID, &session) != nil || !active[session] {
			continue
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.ProcessID)
		if e != nil {
			continue
		}
		var b [windows.MAX_LONG_PATH]uint16
		n := uint32(len(b))
		if windows.QueryFullProcessImageName(h, 0, &b[0], &n) == nil && strings.EqualFold(windows.UTF16ToString(b[:n]), exe) {
			delete(active, session)
		}
		windows.CloseHandle(h)
	}
	out := []uint32{}
	for s := range active {
		out = append(out, s)
	}
	return out
}

// startCompanion starts the companion as the session's signed-in user, on
// that user's desktop, as the Run key would.
func startCompanion(session uint32, exe string) error {
	var token windows.Token
	if e := windows.WTSQueryUserToken(session, &token); e != nil {
		return e
	}
	defer token.Close()
	var env *uint16
	if e := windows.CreateEnvironmentBlock(&env, token, false); e != nil {
		return e
	}
	defer windows.DestroyEnvironmentBlock(env)
	app, e := windows.UTF16PtrFromString(exe)
	if e != nil {
		return e
	}
	line, e := windows.UTF16PtrFromString(`"` + exe + `" --background`)
	if e != nil {
		return e
	}
	dir, e := windows.UTF16PtrFromString(filepath.Dir(exe))
	if e != nil {
		return e
	}
	desk, e := windows.UTF16PtrFromString(`winsta0\default`)
	if e != nil {
		return e
	}
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desk}
	var pi windows.ProcessInformation
	if e = windows.CreateProcessAsUser(token, app, line, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, env, dir, &si, &pi); e != nil {
		return e
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
