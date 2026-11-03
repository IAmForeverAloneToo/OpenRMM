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
// install or update of the agent replaces its file while it runs (Windows
// Installer moves the running file aside), and until the next sign-in remote
// desktop is unavailable; so the installed SYSTEM agent ends companions whose
// file was replaced or removed, and starts the installed one in every active
// signed-in session that has none, at most once every five minutes per
// session.

const companionCheck = 30 * time.Second
const companionRetry = 5 * time.Minute

// EnsureCompanions runs until ctx ends. exe is the installed companion.
func EnsureCompanions(ctx context.Context, exe string, logger *slog.Logger) {
	if _, e := os.Stat(exe); e != nil {
		return
	}
	last := map[uint32]time.Time{}
	for {
		missing, ended := sessionsWithoutCompanion(exe)
		if ended > 0 {
			logger.Info("desktop companions of a replaced agent ended", "count", ended)
		}
		for _, session := range missing {
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
// which the installed companion is not running, after ending companions in
// any user session whose file was replaced or removed (it returns how many).
func sessionsWithoutCompanion(exe string) ([]uint32, int) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if windows.WTSEnumerateSessions(0, 0, 1, &info, &count) != nil {
		return nil, 0
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	active := map[uint32]bool{}
	for _, s := range unsafe.Slice(info, count) {
		if s.State == windows.WTSActive && s.SessionID != 0 {
			active[s.SessionID] = true
		}
	}
	snap, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, 0
	}
	defer windows.CloseHandle(snap)
	ended := 0
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snap, &p); e == nil; e = windows.Process32Next(snap, &p) {
		if !strings.EqualFold(windows.UTF16ToString(p.ExeFile[:]), filepath.Base(exe)) {
			continue
		}
		var session uint32
		if windows.ProcessIdToSessionId(p.ProcessID, &session) != nil || session == 0 {
			continue
		}
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, p.ProcessID)
		if e != nil {
			continue
		}
		var b [windows.MAX_LONG_PATH]uint16
		n := uint32(len(b))
		if windows.QueryFullProcessImageName(h, 0, &b[0], &n) == nil {
			image := windows.UTF16ToString(b[:n])
			if strings.EqualFold(image, exe) {
				delete(active, session)
			} else if replaced(image, exe) && windows.TerminateProcess(h, 0) == nil {
				ended++
			}
		}
		windows.CloseHandle(h)
	}
	out := []uint32{}
	for s := range active {
		out = append(out, s)
	}
	return out, ended
}

// replaced reports whether a companion runs from a file that is no longer a
// companion: renamed aside by Windows Installer when an install or update
// replaced it (into Config.Msi), or deleted by an uninstall. A companion
// started from another folder under its own name is left alone.
func replaced(image, exe string) bool {
	if strings.EqualFold(image, exe) {
		return false
	}
	if !strings.EqualFold(filepath.Base(image), filepath.Base(exe)) {
		return true
	}
	_, e := os.Stat(image)
	return e != nil
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
