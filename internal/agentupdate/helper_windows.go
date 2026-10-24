package agentupdate

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// HelperFlag starts the on-demand update helper: a copy of the agent that
// hosts the update engine while Windows Installer replaces the agent.
const HelperFlag = "--update-helper"

func isSystem() bool {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	return e == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// EnsureJournal creates the update folders and journal on first use. The
// replay counter starts at the release sequence built into this agent, or the
// counter of an older, separate updater if that is higher, so an
// older signed release can never be installed again. While no update is in
// progress the journal follows the agent actually installed, so an MSI
// installed by hand does not block later self-updates.
func EnsureJournal(n *MSIPlatform) error {
	for _, d := range []string{n.update, n.packages} {
		if e := os.MkdirAll(d, 0700); e != nil {
			return e
		}
	}
	current, e := n.Current()
	if e != nil {
		return e
	}
	if raw, e := os.ReadFile(n.JournalPath()); e == nil {
		var j Journal
		if len(raw) > 1024*1024 || Decode(raw, &j) != nil || j.Format != 1 {
			return ErrInvalid
		}
		if j.Active != "" || j.Current == current && j.HighWater >= SequenceFloor() {
			return nil
		}
		j.Current = current
		j.HighWater = max(j.HighWater, SequenceFloor())
		return SaveJSON(n.JournalPath(), j)
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	high := SequenceFloor()
	var old Journal
	if raw, e := os.ReadFile(filepath.Join(filepath.Dir(n.data), "OpenRMM Agent Updater", "journal.json")); e == nil && len(raw) <= 1024*1024 && Decode(raw, &old) == nil && old.HighWater > high {
		high = old.HighWater
	}
	return SaveJSON(n.JournalPath(), Journal{Format: 1, Current: current, HighWater: high, Records: []Record{}})
}

// HelperMain runs the update engine until it has been idle for two minutes.
// Only one helper can run: the pipe is created with FILE_FLAG_FIRST_PIPE_INSTANCE.
func HelperMain() int {
	if !isSystem() {
		return 5
	}
	n, e := NewMSI()
	if e != nil || EnsureJournal(n) != nil {
		return 5
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, e := NewBroker(ctx, n.JournalPath(), len(Keys()) > 0, n, n.Policy)
	if e != nil {
		return 5
	}
	// The pipe admits SYSTEM and Administrators; the agent runs as SYSTEM.
	pipeCtx, stopPipe := context.WithCancel(context.Background())
	defer stopPipe()
	done := make(chan error, 1)
	go func() { done <- ServePipe(pipeCtx, b, "S-1-5-18") }()
	idle := time.Now()
	for {
		select {
		case <-done:
			return 1
		case <-time.After(time.Second):
		}
		if !b.Idle() {
			idle = time.Now()
		} else if time.Since(idle) > 2*time.Minute {
			cancel()
			<-b.Drain()
			return 0
		}
	}
}

// launchHelper starts the helper from a copy outside the program folder, so
// Windows Installer can replace the agent while it runs. It is detached from
// the agent service and survives the service being stopped.
func launchHelper(n *MSIPlatform) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	helper := filepath.Join(n.update, "openrmm-update-helper.exe")
	if e = removeFixed(helper); e != nil {
		// In use: a helper is already running.
		return nil
	}
	if e = copyFixed(exe, helper); e != nil {
		return e
	}
	start := func(flags uint32) error {
		c := exec.Command(helper, HelperFlag)
		c.Dir = n.update
		c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
		if e := c.Start(); e != nil {
			return e
		}
		return c.Process.Release()
	}
	base := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	if e = start(base | windows.CREATE_BREAKAWAY_FROM_JOB); e != nil {
		e = start(base)
	}
	return e
}

type agentClient struct{ pipe pipeAdapter }

// NewAgentClient is the agent's side of self-update: support and results come
// from the helper while it runs and from the journal otherwise.
func NewAgentClient() Client { return agentClient{} }

func (c agentClient) Probe(ctx context.Context) (protocol.AgentUpgradeSupport, error) {
	if s, e := c.pipe.probe(ctx); e == nil {
		return s, nil
	}
	n, e := NewMSI()
	if e != nil {
		return protocol.AgentUpgradeSupport{}, e
	}
	if e = EnsureJournal(n); e != nil {
		return protocol.AgentUpgradeSupport{}, e
	}
	s := JournalSupport(n.JournalPath())
	// Without a verified rollback package for the running agent an update is
	// refused; say so now instead of offering an update that will be denied.
	if s.Broker == "enabled" {
		if r, e := n.installedRelease(); e != nil || AgentHash(r.Manifest) != s.CurrentHash {
			s.Broker = "disabled"
		}
	}
	return s, nil
}
func (c agentClient) Submit(ctx context.Context, q protocol.AgentUpgradeJob) (protocol.AgentUpgradeResult, error) {
	n, e := NewMSI()
	if e != nil || EnsureJournal(n) != nil {
		return protocol.AgentUpgradeResult{}, ErrInvalid
	}
	if _, e = c.pipe.probe(ctx); e != nil {
		if e = launchHelper(n); e != nil {
			return protocol.AgentUpgradeResult{}, e
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			if _, e = c.pipe.probe(ctx); e == nil {
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return protocol.AgentUpgradeResult{}, ErrInvalid
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	return c.pipe.Submit(ctx, q)
}
func (c agentClient) Status(ctx context.Context, id string) (protocol.AgentUpgradeResult, error) {
	if r, e := c.pipe.Status(ctx, id); e == nil {
		return r, nil
	}
	n, e := NewMSI()
	if e != nil {
		return protocol.AgentUpgradeResult{}, e
	}
	return JournalStatus(n.JournalPath(), id)
}
func (c agentClient) Healthy(ctx context.Context, version string) error {
	return c.pipe.Healthy(ctx, version)
}

// Resume restarts the helper after a reboot or crash interrupted an update,
// so the engine can finish or roll back the recorded transaction.
func Resume() {
	n, e := NewMSI()
	if e != nil {
		return
	}
	var j Journal
	raw, e := os.ReadFile(n.JournalPath())
	if e != nil || Decode(raw, &j) != nil || j.Active == "" {
		return
	}
	if _, e = (pipeAdapter{}).probe(context.Background()); e != nil {
		_ = launchHelper(n)
	}
}

// CleanupLegacy removes the program and data folders of helpers that ran as
// separate services in older versions, once their services are gone, and the
// agent's obsolete local permission files. The journal is created first so
// the old updater's replay counter is carried over before its folder goes.
func CleanupLegacy() {
	if n, e := NewMSI(); e == nil {
		_ = EnsureJournal(n)
		for _, name := range []string{"terminal-policy.json", "file-policy.json", "process-policy.json", "service-policy.json", "process-policy.lock", "service-policy.lock", "installation.json"} {
			if p := filepath.Join(n.data, name); noLinks(p) {
				_ = os.Remove(p)
			}
		}
	}
	program, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return
	}
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return
	}
	m, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return
	}
	defer windows.CloseServiceHandle(m)
	for service, folder := range map[string]string{"OpenRMMAgentUpdater": "OpenRMM Agent Updater", "OpenRMMScriptRunner": "OpenRMM Script Runner", "OpenRMMUpdateBroker": "OpenRMM Update Broker"} {
		name, _ := windows.UTF16PtrFromString(service)
		if h, e := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS); e == nil {
			windows.CloseServiceHandle(h)
			continue
		} else if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			continue
		}
		for _, root := range []string{filepath.Join(program, folder), filepath.Join(data, folder)} {
			if noLinks(root) {
				_ = os.RemoveAll(root)
			}
		}
	}
}
