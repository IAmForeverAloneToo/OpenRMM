package processes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/selfprotect"
)

// Case actions: kill a process or a process tree. Every process is
// checked like the RMM's process end (self-protection, critical processes,
// identity by start time) and its image is hashed before it is ended.

type entry struct {
	pid, parent uint32
	name        string
}

func snapshot() (map[uint32]entry, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(h)
	p := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	out := map[uint32]entry{}
	for e = windows.Process32First(h, &p); e == nil && len(out) < maxListed; e = windows.Process32Next(h, &p) {
		out[p.ProcessID] = entry{p.ProcessID, p.ParentProcessID, windows.UTF16ToString(p.ExeFile[:])}
	}
	if e != nil && !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		return nil, e
	}
	return out, nil
}

// Image returns a process's full image path.
func image(h windows.Handle) string {
	var b [32768]uint16
	n := uint32(len(b))
	if windows.QueryFullProcessImageName(h, 0, &b[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(b[:n])
}

const killRights = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_TERMINATE | windows.SYNCHRONIZE

// caseManageable is the first check of a case kill: never the system's
// lowest PIDs, the agent itself or OpenRMM's executables.
func caseManageable(pid uint32, name string) bool {
	return pid > 4 && pid != uint32(os.Getpid()) && Name(name) && !selfprotect.Executable(name)
}

// systemImage reports an image in the Windows system folder (System32 or
// SysWOW64).
func systemImage(full string) bool {
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return true // fail closed: treat as genuine
	}
	dir := filepath.Dir(full)
	return strings.EqualFold(dir, system) || strings.EqualFold(dir, filepath.Join(filepath.Dir(system), "SysWOW64"))
}

// caseSafe checks a held process for a case kill: its image must have the
// expected name and not be OpenRMM's, Windows must not mark it critical, and
// a protected Windows name is refused only for the genuine system image.
func caseSafe(h windows.Handle, pid uint32, name string) bool {
	if !caseManageable(pid, name) || isCritical.Find() != nil {
		return false
	}
	full := image(h)
	if full == "" || !strings.EqualFold(filepath.Base(full), name) || selfprotect.Executable(filepath.Base(full)) {
		return false
	}
	var critical uint32
	if r, _, _ := isCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&critical))); r == 0 || critical != 0 {
		return false
	}
	return !ProtectedName(name) || !systemImage(full)
}

// CanKill reports whether a listed process (identified by PID, name and start)
// may be ended by a case action.
func CanKill(pid uint32, name, start string) bool {
	if !caseManageable(pid, name) {
		return false
	}
	h, e := windows.OpenProcess(killRights, false, pid)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	s, _, e := counters(h)
	return e == nil && s == start && caseSafe(h, pid, name)
}

type target struct {
	entry
	h             windows.Handle
	start         string
	depth         int
	image, sha256 string
}

// maxTree bounds a tree kill.
const maxTree = 1024

// parentOf reads a process's parent PID through its handle, which is bound
// to that process (unlike a snapshot entry, whose PID may be reused).
func parentOf(h windows.Handle) (uint32, bool) {
	var b windows.PROCESS_BASIC_INFORMATION
	if windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&b), uint32(unsafe.Sizeof(b)), nil) != nil {
		return 0, false
	}
	return uint32(b.InheritedFromUniqueProcessId), true
}

// Kill ends the process an action names and, with Tree, its descendants
// first. A descendant is a process whose parent (read through its own handle)
// is in the tree and which started after that parent, so a reused PID does
// not adopt unrelated processes. A protected or changed root ends nothing.
// truncated reports a tree larger than maxTree; the rest is left running.
func Kill(ctx context.Context, a protocol.ResponseAction, hash func(string) (string, string)) (results []protocol.KillResult, truncated bool) {
	root := protocol.KillResult{PID: a.PID, Name: a.Name, Start: a.Start, Outcome: "denied"}
	if !caseManageable(a.PID, a.Name) || !Start(a.Start) {
		return []protocol.KillResult{root}, false
	}
	all, e := snapshot()
	if e != nil {
		root.Outcome = "failed"
		return []protocol.KillResult{root}, false
	}
	first, ok := all[a.PID]
	if !ok {
		root.Outcome = "not_found"
		return []protocol.KillResult{root}, false
	}
	root.ParentPID = first.parent
	h, e := windows.OpenProcess(killRights, false, a.PID)
	if e != nil {
		if errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
			root.Outcome = "not_found"
		}
		return []protocol.KillResult{root}, false
	}
	start, _, e := counters(h)
	if e != nil || start != a.Start || !strings.EqualFold(first.name, a.Name) {
		windows.CloseHandle(h)
		root.Outcome = "identity_changed"
		return []protocol.KillResult{root}, false
	}
	if !caseSafe(h, a.PID, a.Name) {
		windows.CloseHandle(h)
		return []protocol.KillResult{root}, false
	}
	targets := []target{{entry: first, h: h, start: start}}
	seen := map[uint32]bool{a.PID: true}
	if a.Tree {
		for i := 0; i < len(targets) && !truncated; i++ {
			parent := targets[i]
			for _, c := range all {
				if c.parent != parent.pid || seen[c.pid] {
					continue
				}
				if len(targets) == maxTree {
					truncated = true
					break
				}
				ch, e := windows.OpenProcess(killRights, false, c.pid)
				if e != nil {
					continue
				}
				s, _, e := counters(ch)
				actual, ok := parentOf(ch)
				if e != nil || !ok || actual != parent.pid || !startsAfter(s, parent.start) {
					windows.CloseHandle(ch)
					continue
				}
				seen[c.pid] = true
				targets = append(targets, target{entry: c, h: ch, start: s, depth: parent.depth + 1})
			}
		}
	}
	defer func() {
		for _, t := range targets {
			windows.CloseHandle(t.h)
		}
	}()
	// Images are read and hashed before anything ends: a parent may exit on
	// its own once its children are gone.
	for i := range targets {
		targets[i].image = image(targets[i].h)
		if hash != nil {
			targets[i].sha256, _ = hash(targets[i].image)
		}
	}
	// Deepest first, the requested process last.
	order := append([]target(nil), targets...)
	sortByDepth(order)
	out := []protocol.KillResult{}
	for _, t := range order {
		out = append(out, end(ctx, t, hash))
	}
	return out, truncated
}

// sortByDepth orders deeper processes first (stable).
func sortByDepth(t []target) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].depth > t[j-1].depth; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}

func startsAfter(child, parent string) bool {
	return len(child) > len(parent) || len(child) == len(parent) && child >= parent
}

func end(ctx context.Context, t target, hash func(string) (string, string)) protocol.KillResult {
	r := protocol.KillResult{PID: t.pid, ParentPID: t.parent, Name: t.name, Start: t.start, Image: t.image, SHA256: t.sha256, Outcome: "denied"}
	// The held handle keeps the identity; a process that already ended (for
	// example a shell whose children were just ended) is reported as such.
	if s, e := windows.WaitForSingleObject(t.h, 0); e == nil && s == windows.WAIT_OBJECT_0 {
		r.Outcome = "exited"
		return r
	}
	if !caseSafe(t.h, t.pid, t.name) {
		return r
	}
	if ctx.Err() != nil {
		r.Outcome = "failed"
		return r
	}
	if e := windows.TerminateProcess(t.h, 1); e != nil {
		r.Outcome = "failed"
		return r
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, e := windows.WaitForSingleObject(t.h, 100); e == nil && s == windows.WAIT_OBJECT_0 {
			r.Outcome = "succeeded"
			return r
		}
	}
	r.Outcome = "failed"
	return r
}
