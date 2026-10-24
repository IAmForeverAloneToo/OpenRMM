package agentupdate

import (
	"context"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// MSIPlatform updates the installed agent through signed Windows Installer
// packages. It runs in the on-demand update helper, a copy of the
// agent outside its program folder, so Windows Installer can stop and replace
// the agent service while the helper waits for the new agent's health proof.
// The previous package is kept as the rollback package.
type MSIPlatform struct {
	root, data, state, update, packages, target string
	mu                                          sync.Mutex
	old, new, candidate                         string
	started                                     time.Time
}

func NewMSI() (*MSIPlatform, error) {
	program, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return nil, e
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return nil, e
	}
	n := &MSIPlatform{root: filepath.Join(program, "OpenRMM Agent"), data: filepath.Join(data, "OpenRMM Agent")}
	n.state = filepath.Join(n.data, "state")
	n.update = filepath.Join(n.data, "update")
	n.packages = filepath.Join(n.data, "packages")
	n.target = filepath.Join(n.root, "openrmm-agent.exe")
	return n, nil
}
func (n *MSIPlatform) JournalPath() string { return filepath.Join(n.update, "journal.json") }
func (n *MSIPlatform) Installer() string   { return "msi" }

func noLinks(p string) bool {
	for {
		u, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return false
		}
		a, e := windows.GetFileAttributes(u)
		if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return false
		}
		parent := filepath.Dir(p)
		if p == parent {
			return true
		}
		p = parent
	}
}

// owned accepts only SYSTEM or Administrators as owner and refuses write
// access for anyone else. The agent locks its data folder down this way at
// start-up; the update state lives inside it.
func owned(p string) bool {
	if !noLinks(p) {
		return false
	}
	sd, e := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return false
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return false
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return false
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &a) != nil {
			return false
		}
		if a.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		if !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && uint32(a.Mask)&0x500d0156 != 0 {
			return false
		}
	}
	return true
}

// Policy pins the keys built into this agent. Without keys (a development
// build) the helper still loads but every update is denied.
func (n *MSIPlatform) Policy() (Policy, error) {
	if !owned(n.data) {
		return Policy{}, ErrInvalid
	}
	return Policy{Format: 1, Keys: Keys()}, nil
}

// trustedCommand accepts only the installed agent's fixed executable, state and
// log paths, optionally followed by the known feature switches in their fixed
// order (written by scripts/service.ps1 in older versions).
func (n *MSIPlatform) trustedCommand(command string) bool {
	base := fmt.Sprintf(`"%s" -service -state "%s" -log-directory "%s"`, n.target, n.state, filepath.Join(n.data, "logs"))
	pattern := "^" + regexp.QuoteMeta(base) + `(?: -inventory=(true|false) -inventory-interval ([1-9]|1[0-5])m)?(?: -disk-space=(true|false))?(?: -memory=(true|false))?(?: -cpu=(true|false))?(?: -uptime=(true|false))?(?: -services=(true|false))?(?: -event-logs=(true|false))?(?: -windows-updates=(true|false))?(?: -software=(true|false))?(?: -processes=(true|false))?(?: -scripts=(true|false))?(?: -desktop=(true|false))?(?: -terminal=(true|false))?(?: -files=(true|false))?$`
	return regexp.MustCompile(pattern).MatchString(command)
}
func (n *MSIPlatform) service() (*mgr.Mgr, *mgr.Service, error) {
	managerHandle, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, nil, operationFailure("manager_open", e)
	}
	m := &mgr.Mgr{Handle: managerHandle}
	name, _ := windows.UTF16PtrFromString("OpenRMMAgent")
	serviceHandle, e := windows.OpenService(managerHandle, name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS|windows.SERVICE_START|windows.SERVICE_STOP)
	s := &mgr.Service{Name: "OpenRMMAgent", Handle: serviceHandle}
	if e != nil {
		m.Disconnect()
		return nil, nil, operationFailure("service_open", e)
	}
	c, e := s.Config()
	if e != nil || !n.trustedCommand(c.BinaryPathName) || !strings.EqualFold(c.ServiceStartName, "LocalSystem") {
		s.Close()
		m.Disconnect()
		return nil, nil, ErrInvalid
	}
	return m, s, nil
}
func (n *MSIPlatform) Current() (string, error) {
	if _, e := os.Lstat(n.target); e != nil {
		return "", e
	}
	if !noLinks(n.target) {
		return "", ErrInvalid
	}
	h, _, e := FileHash(n.target)
	return h, e
}
func readPinned(path string) (*os.File, error) {
	u, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(u, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, ErrInvalid
	}
	return os.NewFile(uintptr(h), path), nil
}
func copyFixed(source, dest string) error {
	f, e := readPinned(source)
	if e != nil {
		return e
	}
	defer f.Close()
	out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(out, io.LimitReader(f, MaxArtifact+1))
	if e == nil && n > MaxArtifact {
		e = ErrInvalid
	}
	if e == nil {
		e = out.Sync()
	}
	ce := out.Close()
	if e == nil {
		e = ce
	}
	return e
}
func removeFixed(path string) error {
	e := os.Remove(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
func replaceFixed(source, dest string) error {
	a, _ := windows.UTF16PtrFromString(source)
	b, _ := windows.UTF16PtrFromString(dest)
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// installedRelease is the signed release of the package currently installed,
// kept as the rollback package. It must verify against a pinned key.
func (n *MSIPlatform) installedRelease() (protocol.SignedAgentRelease, error) {
	var r protocol.SignedAgentRelease
	f, e := readPinned(filepath.Join(n.packages, "current.json"))
	if e != nil {
		return r, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	f.Close()
	if e != nil || len(raw) > 16384 || Decode(raw, &r) != nil || !MSI(r.Manifest) {
		return r, ErrInvalid
	}
	for _, k := range Keys() {
		if Verify(r, k) {
			return r, Inspect(filepath.Join(n.packages, "current.msi"), r.Manifest)
		}
	}
	return r, ErrInvalid
}
func (n *MSIPlatform) Prepare(q protocol.AgentUpgradeJob) error {
	if !MSI(q.Release.Manifest) || !noLinks(n.state) || !owned(n.update) {
		return ErrInvalid
	}
	// Without a verified rollback package a failed install could leave the
	// device without an agent; refuse rather than risk it.
	current, e := n.installedRelease()
	if e != nil || AgentHash(current.Manifest) != q.ExpectedHash {
		return operationFailure("rollback_package", ErrInvalid)
	}
	candidate := filepath.Join(n.update, "candidate.msi")
	if e = removeFixed(candidate); e != nil {
		return e
	}
	if e = copyFixed(filepath.Join(n.state, "agent-release-"+q.ID+".msi"), candidate); e != nil {
		return e
	}
	if e = Inspect(candidate, q.Release.Manifest); e != nil {
		return e
	}
	n.mu.Lock()
	n.old, n.new, n.candidate = q.ExpectedHash, AgentHash(q.Release.Manifest), q.Release.Manifest.Hash
	n.mu.Unlock()
	return nil
}
func (n *MSIPlatform) Stop(ctx context.Context) error {
	m, s, e := n.service()
	if e != nil {
		// Windows Installer may have removed the registration mid-update; a
		// missing service is already stopped.
		if errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return e
	}
	defer m.Disconnect()
	defer s.Close()
	status, e := s.Query()
	if e != nil {
		return operationFailure("status_query", e)
	}
	if status.State == svc.Stopped {
		return nil
	}
	var proc windows.Handle
	if status.ProcessId != 0 {
		proc, e = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
		if e != nil {
			return operationFailure("process_query_handle", e)
		}
		defer windows.CloseHandle(proc)
	}
	if _, e = s.Control(svc.Stop); e != nil && status.State != svc.StopPending {
		return operationFailure("service_stop", e)
	}
	for {
		status, e = s.Query()
		if e != nil {
			return e
		}
		if status.State == svc.Stopped {
			if proc == 0 {
				return nil
			}
			exited, e := processExited(proc)
			if e != nil {
				return operationFailure("process_exit_query", e)
			}
			if exited {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// install runs Windows Installer silently. The package's MajorUpgrade
// (downgrades allowed) removes whichever agent version is installed first.
func (n *MSIPlatform) install(pkg, label string) error {
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return e
	}
	n.mu.Lock()
	n.started = time.Now()
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, filepath.Join(system, "msiexec.exe"), "/i", pkg, "/qn", "/norestart", "REBOOT=ReallySuppress", "/l*v", filepath.Join(n.update, label+".log"))
	e = c.Run()
	if c.ProcessState == nil {
		return operationFailure("msiexec_start", e)
	}
	// 0 success, 3010 success with a restart pending (never forced).
	if code := c.ProcessState.ExitCode(); code != 0 && code != 3010 {
		return operationFailure("msiexec_exit", windows.Errno(code))
	}
	return nil
}
func (n *MSIPlatform) Replace() error {
	n.mu.Lock()
	old, newHash, candidateHash := n.old, n.new, n.candidate
	n.mu.Unlock()
	if hash, e := n.Current(); e != nil || hash != old {
		return ErrInvalid
	}
	candidate := filepath.Join(n.update, "candidate.msi")
	if h, _, e := FileHash(candidate); e != nil || h != candidateHash {
		return ErrInvalid
	}
	if e := n.install(candidate, "install"); e != nil {
		return e
	}
	if hash, e := n.Current(); e != nil || hash != newHash {
		return operationFailure("installed_hash", ErrInvalid)
	}
	return nil
}
func (n *MSIPlatform) Start(ctx context.Context) error {
	m, s, e := n.service()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	defer s.Close()
	if v, e := s.Query(); e == nil && (v.State == svc.Running || v.State == svc.StartPending) {
		return n.waitRunning(ctx, s)
	}
	n.mu.Lock()
	n.started = time.Now()
	n.mu.Unlock()
	if e = s.Start(); e != nil && !errors.Is(e, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return e
	}
	return n.waitRunning(ctx, s)
}
func (n *MSIPlatform) waitRunning(ctx context.Context, s *mgr.Service) error {
	for {
		v, e := s.Query()
		if e != nil {
			return e
		}
		if v.State == svc.Running {
			return nil
		}
		if v.State == svc.Stopped {
			return ErrInvalid
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Restore reinstalls the rollback package (the previously installed release).
func (n *MSIPlatform) Restore(old, newHash string) error {
	if hash, e := n.Current(); e == nil && hash == old {
		return nil
	}
	current, e := n.installedRelease()
	if e != nil || AgentHash(current.Manifest) != old {
		return operationFailure("rollback_package", ErrInvalid)
	}
	if e = n.install(filepath.Join(n.packages, "current.msi"), "rollback"); e != nil {
		return e
	}
	if hash, e := n.Current(); e != nil || hash != old {
		return operationFailure("restored_hash", ErrInvalid)
	}
	return nil
}

// Commit keeps the package that is now installed as the next rollback package.
func (n *MSIPlatform) Commit(q protocol.AgentUpgradeJob) error {
	if e := replaceFixed(filepath.Join(n.update, "candidate.msi"), filepath.Join(n.packages, "current.msi")); e != nil {
		return e
	}
	return SaveJSON(filepath.Join(n.packages, "current.json"), q.Release)
}
func (n *MSIPlatform) Peer(pid uint32, hash string) bool {
	m, s, e := n.service()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	defer s.Close()
	v, e := s.Query()
	if e != nil || v.State != svc.Running || v.ProcessId != pid || pid == 0 {
		return false
	}
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var created, exit, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exit, &kernel, &user) != nil {
		return false
	}
	n.mu.Lock()
	started := n.started
	n.mu.Unlock()
	if created.Nanoseconds() < started.UnixNano() {
		return false
	}
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	u, e := token.GetTokenUser()
	if e != nil || !u.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return false
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &size) != nil || !strings.EqualFold(windows.UTF16ToString(buf[:size]), n.target) {
		return false
	}
	current, e := n.Current()
	return e == nil && current == hash
}
func (n *MSIPlatform) Active(hash string) bool {
	m, s, e := n.service()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	defer s.Close()
	v, e := s.Query()
	return e == nil && n.Peer(v.ProcessId, hash)
}

func processExited(h windows.Handle) (bool, error) {
	var exit uint32
	e := windows.GetExitCodeProcess(h, &exit)
	return e == nil && exit != 259, e
}
