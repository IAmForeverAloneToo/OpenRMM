package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/inventory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/isolation"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/localaccounts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/logons"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/processes"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/response"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/securitystatus"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sessions"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/software"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/sysinfo"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/winservices"
	"path/filepath"
)

var Version = "0.1.0-dev"

var (
	ErrDeviceRejected  = errors.New("device credentials or enrollment token were rejected; use administrator-authorized recovery")
	ErrDeviceThrottled = errors.New("device request was throttled; wait a minute before retrying")
	ErrRequestRejected = errors.New("device request was rejected; check agent/server compatibility before retrying")
	// ErrDeviceRevoked is a rejection the server explicitly marked as revocation.
	ErrDeviceRevoked = errors.New("device identity was revoked by an administrator; re-enroll after authorized recovery")
)

type heartbeatSession struct {
	transportMu sync.RWMutex
	config      config.Agent
	value       credentials
	certificate *x509.Certificate
	client      *http.Client
	transport   *http.Transport
	metadata    protocol.Heartbeat
	// isolation is the device's network isolation; nil in tests.
	isolation          *isolation.Manager
	isolationRefreshed time.Time
	// disabled is the policy setting this run applied; onFeatures is called
	// when a heartbeat reply asks for different settings.
	disabled   []string
	onFeatures func([]string)
	now        func() time.Time
	nextRenew  time.Time
	logger     *slog.Logger
	// revoked is set when the server marks this identity revoked and cleared by
	// the next accepted heartbeat (for example after a mistaken restore).
	revoked atomic.Bool
	// skewNoticed and renewNoticed limit repeated local warnings.
	skewNoticed, renewNoticed time.Time
	// hashes caches image hashes for response actions.
	hashes response.HashCache
	// wake replaces idle polling with one work wait (wake.go); nil in tests.
	wake    *waker
	desktop desktopRelay
	// proxyNote is the proxy last logged (proxy.go).
	proxyNote string
	// started and protected time the move of a plain device key into
	// protected storage (protectAfter).
	started   time.Time
	protected bool
}

// protectAfter delays moving version 1 credentials to version 2 until an
// agent update has long passed its health check (90 seconds), so the update
// can no longer be rolled back to an agent that cannot read them.
const protectAfter = 10 * time.Minute

func newHeartbeatSession(c config.Agent, metadata protocol.Heartbeat) (*heartbeatSession, error) {
	if !metadata.Valid() {
		return nil, errors.New("heartbeat collection currently requires valid Windows x64 metadata")
	}
	s := &heartbeatSession{config: c, metadata: metadata, now: time.Now, logger: slog.Default(), started: time.Now()}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *heartbeatSession) reload() error {
	value, _, pair, err := loadCredentials(s.config.State)
	if err != nil {
		return err
	}
	roots, err := trust(value.ServerCA)
	if err != nil {
		return err
	}
	cert, err := deviceidentity.ParseCertificate(value.Credential.Certificate)
	if err != nil {
		return errors.New("cannot read saved device certificate")
	}
	// A few idle connections, so the held work wait and the workers reuse
	// connections instead of each request starting a new TLS handshake.
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}, Proxy: proxyFunc(s.config.State), MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second}
	if note := proxies.describe(s.config.State, value.DeviceURL); note != s.proxyNote {
		s.logger.Info("server connection", "proxy", note)
		s.proxyNote = note
	}
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	s.value = value
	s.certificate = cert
	s.transport = transport
	s.client = &http.Client{Transport: transport, Timeout: s.config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}
func (s *heartbeatSession) close() {
	s.transportMu.Lock()
	defer s.transportMu.Unlock()
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}
func (s *heartbeatSession) pulse(ctx context.Context) error {
	now := s.now()
	// The server's clock decides certificate validity. A local clock outside the
	// certificate window is reported, not treated as rejection.
	if (now.Before(s.certificate.NotBefore) || !now.Before(s.certificate.NotAfter)) && now.Sub(s.skewNoticed) >= time.Hour {
		s.logger.Warn("device clock is outside the certificate validity window; check the system time", "not_before", s.certificate.NotBefore.UTC().Format(time.RFC3339), "not_after", s.certificate.NotAfter.UTC().Format(time.RFC3339))
		s.skewNoticed = now
	}
	if !s.revoked.Load() && !now.Before(s.nextRenew) && s.certificate.NotAfter.Sub(now) <= 7*24*time.Hour {
		// A failed renewal never suppresses the heartbeat; it is retried hourly.
		_, err := Renew(ctx, s.config)
		if err == nil {
			err = s.reload()
		}
		if err == nil {
			s.nextRenew = now.Add(6 * time.Hour)
		} else {
			if errors.Is(err, ErrDeviceRevoked) {
				s.revoked.Store(true)
			}
			s.nextRenew = now.Add(time.Hour)
			if now.Sub(s.renewNoticed) >= 6*time.Hour {
				s.logger.Warn("certificate renewal failed; retrying hourly", "expires", s.certificate.NotAfter.UTC().Format(time.RFC3339))
				s.renewNoticed = now
			}
		}
	}
	err := s.heartbeat(ctx)
	if err == nil && !s.protected && now.Sub(s.started) >= protectAfter {
		s.protected = true
		if moved, e := protectCredentials(s.config.State); e != nil {
			s.logger.Warn("cannot protect the device key; it stays as it is until the next start", "reason", e.Error())
		} else if moved {
			s.logger.Info("device key encrypted with DPAPI; the next certificate renewal moves to a new key")
		}
	}
	if err == nil && s.config.Service {
		healthCtx, cancel := context.WithTimeout(ctx, time.Second)
		_ = agentupdate.NewClient().Healthy(healthCtx, Version)
		cancel()
	}
	return err
}

func (s *heartbeatSession) send(ctx context.Context, path string, input any) error {
	var receipt protocol.HeartbeatReceipt
	if err := s.call(ctx, path, input, &receipt); err != nil {
		return err
	}
	return s.checkReceipt(receipt)
}

func (s *heartbeatSession) checkReceipt(receipt protocol.HeartbeatReceipt) error {
	s.transportMu.RLock()
	id := s.value.Credential.DeviceID
	s.transportMu.RUnlock()
	if receipt.DeviceID != id || receipt.ReceivedAt <= 0 {
		return errors.New("server returned an invalid heartbeat receipt")
	}
	return nil
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func retryJitter(base time.Duration) time.Duration {
	return base/2 + time.Duration(rand.Int64N(int64(base-base/2)+1))
}

// runHeartbeatLoop keeps retry state separate from collection/transport so its
// timing, transition logs, and cancellation can be tested without real sleeps.
func runHeartbeatLoop(ctx context.Context, interval time.Duration, logger *slog.Logger, pulse func(context.Context) error, wait func(context.Context, time.Duration) bool, now func() time.Time, jitter func(time.Duration) time.Duration) error {
	connected := false
	failures := 0
	backoff := time.Second
	var lastNotice time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := pulse(ctx)
		if ctx.Err() != nil {
			return nil
		}
		delay := interval
		if err == nil {
			if !connected {
				logger.Info("agent connected; heartbeats active")
			}
			connected = true
			failures = 0
			backoff = time.Second
		} else {
			// Only cancellation ends the loop. A confirmed revocation pauses all
			// work and re-checks hourly; other rejections back off longer than
			// connectivity failures but are always retried.
			limit := time.Minute
			if errors.Is(err, ErrDeviceRejected) || errors.Is(err, ErrRequestRejected) {
				limit = 5 * time.Minute
			}
			delay = jitter(backoff)
			switch {
			case errors.Is(err, ErrDeviceRevoked):
				delay = time.Hour
			case errors.Is(err, ErrDeviceThrottled):
				delay = time.Minute
			}
			if connected || failures == 0 || now().Sub(lastNotice) >= 15*time.Minute {
				switch {
				case errors.Is(err, ErrDeviceRevoked):
					logger.Error("device identity revoked by an administrator; all work paused, re-checking hourly", "retry_after", delay.String())
				case errors.Is(err, ErrDeviceRejected), errors.Is(err, ErrRequestRejected):
					logger.Warn("heartbeat rejected by the server or an intermediary; retrying", "reason", err.Error(), "retry_after", delay.String())
				default:
					logger.Warn("heartbeat unavailable; retrying", "retry_after", delay.String())
				}
				lastNotice = now()
			}
			connected = false
			failures++
			backoff = min(backoff*2, limit)
		}
		if !wait(ctx, delay) {
			return nil
		}
	}
}

// heartbeat sends the heartbeat and applies the policy settings in its reply.
func (s *heartbeatSession) heartbeat(ctx context.Context) error {
	s.transportMu.RLock()
	id := s.value.Credential.DeviceID
	s.transportMu.RUnlock()
	var receipt protocol.HeartbeatReceipt
	metadata := s.metadata
	if s.isolation != nil {
		state := s.isolation.State()
		if state.Isolated || state.Released != "" {
			s.refreshIsolation(ctx, state)
			metadata.Isolation = &state
		}
	}
	if err := s.call(ctx, heartbeatPath, metadata, &receipt); err != nil {
		return err
	}
	if receipt.DeviceID != id || receipt.ReceivedAt <= 0 {
		return errors.New("server returned an invalid heartbeat receipt")
	}
	if s.onFeatures != nil && featuresChanged(s.disabled, receipt.Disabled) {
		received := receipt.Disabled
		if received == nil {
			received = []string{}
		}
		s.onFeatures(received)
	}
	return nil
}

// Run uses an existing identity. It never re-enrolls an enrolled device or
// deletes keys; an installed service without one first enrolls with the
// installer's enrollment file.
// When the device's policy changes which features are on, the agent's work is
// restarted with the new settings; the process and its identity stay.
func Run(ctx context.Context, c config.Agent, logger *slog.Logger) error {
	if c.Service {
		applyProxyHandoff(c, logger)
		if err := enrollFromFile(ctx, c, logger); err != nil {
			return err
		}
		recordDevice(c, logger)
	}
	for {
		reconfigure, err := runOnce(ctx, c, loadDisabled(c.State), logger)
		if !reconfigure || ctx.Err() != nil {
			return err
		}
		logger.Info("feature settings changed by the device's policy; restarting agent work")
	}
}

func runOnce(ctx context.Context, local config.Agent, disabled []string, logger *slog.Logger) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hostname, err := os.Hostname()
	if err != nil {
		return false, errors.New("cannot read device hostname")
	}
	locked := localLocks(local)
	c := withFeatures(local, locked, disabled)
	metadata := protocol.Heartbeat{Hostname: hostname, OS: runtime.GOOS, Architecture: runtime.GOARCH, AgentVersion: Version, Locked: locked, Features: protocol.AgentFeatures}
	if runtime.GOOS == "windows" {
		metadata.Abilities = []string{protocol.AbilityHunt, protocol.AbilityIsolation, protocol.AbilityPersistence, protocol.AbilityTriage}
	}
	session, err := newHeartbeatSession(c, metadata)
	if err != nil {
		return false, err
	}
	defer session.close()
	session.logger = logger
	if iso, err := newIsolation(configState{state: c.State, service: c.Service}); err != nil {
		logger.Error("network isolation unavailable: its folder could not be prepared", "error", err.Error())
	} else {
		session.isolation = iso
		if err := iso.Restore(); err != nil {
			logger.Error("network isolation could not be applied again", "error", err.Error())
		}
	}
	var reconfigure atomic.Bool
	session.disabled = disabled
	session.onFeatures = func(received []string) {
		if saveDisabled(c.State, received) != nil {
			logger.Error("cannot save feature settings; keeping the current ones")
			return
		}
		reconfigure.Store(true)
		cancel()
	}
	featureDone := make(chan struct{})
	featureInterval := c.InventoryInterval
	if featureInterval <= 0 {
		featureInterval = 15 * time.Minute
	}
	var workers sync.WaitGroup
	wake := newWaker()
	session.wake = wake
	workers.Add(1)
	go func() { defer workers.Done(); session.runWake(ctx, wake) }()
	updateClient := agentupdate.NewAgentClient()
	selfHash := strings.Repeat("0", 64)
	if c.Service {
		// The data folder may have been created by Windows Installer; lock
		// it down, remove leftovers of older separate helpers, and let an
		// update interrupted by a restart finish or roll back.
		if err := privatefs.RestrictInstallation(filepath.Dir(c.State)); err != nil {
			logger.Error("cannot restrict the agent data folder; continuing")
		}
		agentupdate.CleanupLegacy()
		agentupdate.Resume()
		selfPath, _ := os.Executable()
		var hashErr error
		selfHash, _, hashErr = agentupdate.FileHash(selfPath)
		if hashErr != nil {
			return false, errors.New("cannot verify running agent artifact")
		}
		workers.Add(1)
		go func() { defer workers.Done(); session.runAgentUpgrades(ctx, c.State, selfHash, updateClient, logger) }()
	}
	// The agent's own program, state, log and updater folders are never
	// reachable through file transfer, even though the SYSTEM agent can read them.
	executable, _ := os.Executable()
	deny := []string{c.State, c.LogDirectory, filepath.Dir(executable)}
	if c.Service {
		data := filepath.Dir(c.State)
		deny = append(deny, data, filepath.Join(filepath.Dir(data), "OpenRMM Agent Updater"))
	}
	fileAdapter := filetransfer.NewAdapter(deny...)
	if c.Files {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runFileJobs(ctx, fileAdapter, session.pollFile, session.sendFileResult, wake.waiter(protocol.WorkFiles), logger)
		}()
	}
	if c.Response {
		workers.Add(1)
		go func() { defer workers.Done(); session.runEvidence(ctx, deny, logger) }()
	}
	if c.Terminal {
		if identity, e := terminal.Identity(); e == nil {
			workers.Add(1)
			go func() {
				defer workers.Done()
				runTerminal(ctx, c.State, session.terminalExchange, terminal.Start, identity, func() bool { return true }, wake.waiter(protocol.WorkTerminal))
			}()
		} else {
			logger.Warn("interactive terminal unsupported for this OS or account")
		}
	}
	if c.Desktop {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := desktop.ServePipe(ctx, session.desktopExchange); err != nil && ctx.Err() == nil {
				logger.Error("attended desktop pipe unavailable")
			}
		}()
		// The installed agent keeps the companion running in signed-in
		// sessions, also after an install or update stopped it.
		if exe, err := os.Executable(); err == nil && c.Service {
			workers.Add(1)
			go func() {
				defer workers.Done()
				desktop.EnsureCompanions(ctx, filepath.Join(filepath.Dir(exe), "openrmm-desktop.exe"), logger)
			}()
		}
	}
	if c.Scripts {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runScripts(ctx, c.State, session.pollScript, session.scriptProgress, func(ctx context.Context, q protocol.ScriptJob) protocol.ScriptResult {
				return scripting.RunContainedProxy(ctx, c.State, q, scriptProxyFor(c.State, q))
			}, wake.waiter(protocol.WorkScripts), logger)
		}()
	}
	processAdapter := processes.NewAdapter()
	if c.Processes {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runProcessActions(ctx, processAdapter, session.pollProcessAction, func(ctx context.Context, r protocol.ProcessResult) error {
				return session.send(ctx, "/api/v1/agent/process-actions/result", r)
			}, wake.waiter(protocol.WorkProcesses), logger)
		}()
	}
	serviceAdapter := winservices.NewAdapter()
	updateAdapter, updateErr := windowsupdate.NewLocal(ctx, filepath.Join(c.State, "windows-update-journal.json"))
	windowsUpdates := c.WindowsUpdates && updateErr == nil
	if c.WindowsUpdates && updateErr != nil {
		logger.Error("Windows Update journal unreadable; Windows Update management stopped until local recovery")
	}
	if windowsUpdates {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runUpdateJobs(ctx, c.State, updateAdapter, session.pollUpdateJob, func(ctx context.Context, p protocol.UpdateProgress) error {
				return session.send(ctx, "/api/v1/agent/updates/progress", p)
			}, wake.waiter(protocol.WorkUpdates), logger)
		}()
	}
	eventAdapter := eventlogs.NewAdapter()
	if c.EventLogs {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runEventQueries(ctx, eventAdapter, session.pollEventQuery, func(ctx context.Context, r protocol.EventResult) error {
				return session.send(ctx, "/api/v1/agent/event-logs/result", r)
			}, wake.waiter(protocol.WorkEvents), logger)
		}()
	}

	if c.Services {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runServiceActions(ctx, serviceAdapter, session.pollAction, func(ctx context.Context, r protocol.ServiceResult) error {
				return session.send(ctx, "/api/v1/agent/service-actions/result", r)
			}, wake.waiter(protocol.WorkServices), logger)
		}()
	}
	for _, job := range []features.Job{
		{Module: agentupdate.Module{Client: updateClient, Hash: selfHash}, Enabled: c.Service, Interval: time.Minute},
		{Module: filetransfer.Module{Adapter: fileAdapter}, Enabled: c.Files, Interval: time.Minute},
		{Module: scripting.Module{}, Enabled: c.Scripts, Interval: time.Minute},
		{Module: processes.Module{Adapter: processAdapter}, Enabled: c.Processes, Interval: processes.Interval, MaxDataBytes: processes.MaxBytes},
		{Module: software.Module{Collector: software.NewCollector()}, Enabled: c.Software, Interval: software.Interval, MaxDataBytes: software.MaxBytes, Timeout: software.Timeout},
		{Module: sessions.Module{Collector: sessions.NewCollector()}, Enabled: c.Sessions, Interval: sessions.Interval, MaxDataBytes: sessions.MaxBytes},
		{Module: &logons.Module{Reader: logons.NewReader(), Path: filepath.Join(c.State, "logon-cursor.json")}, Enabled: c.Sessions, Interval: logons.Interval, MaxDataBytes: logons.MaxBytes, Timeout: logons.Timeout},
		{Module: localaccounts.Module{Collector: localaccounts.NewCollector()}, Enabled: c.LocalAccounts, Interval: localaccounts.Interval, MaxDataBytes: localaccounts.MaxBytes},
		{Module: windowsupdate.Module{Adapter: updateAdapter}, Enabled: windowsUpdates, Interval: time.Minute},
		{Module: eventlogs.Module{Adapter: eventAdapter}, Enabled: c.EventLogs, Interval: time.Minute},
		{Module: inventory.Module{Collector: inventory.NewCollector(Version)}, Enabled: c.Inventory, Interval: featureInterval},
		{Module: sysinfo.Module{Collector: sysinfo.NewCollector()}, Enabled: c.Inventory, Interval: featureInterval, MaxDataBytes: sysinfo.MaxBytes},
		{Module: securitystatus.Module{Collector: securitystatus.NewCollector()}, Enabled: c.Inventory, Interval: securitystatus.Interval, MaxDataBytes: securitystatus.MaxBytes, Timeout: securitystatus.Timeout},
		{Module: diskspace.Module{Collector: diskspace.NewCollector()}, Enabled: c.DiskSpace, Interval: diskspace.Interval},
		{Module: memory.Module{Collector: memory.NewCollector()}, Enabled: c.Memory, Interval: memory.Interval},
		{Module: cpu.Module{Collector: cpu.NewCollector()}, Enabled: c.CPU, Interval: cpu.Interval},
		{Module: winservices.Module{Adapter: serviceAdapter}, Enabled: c.Services, Interval: winservices.Interval, MaxDataBytes: winservices.MaxBytes},
		{Module: uptime.Module{Collector: uptime.NewCollector()}, Enabled: c.Uptime, Interval: uptime.Interval},
	} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			features.Run(ctx, job, func(ctx context.Context, report protocol.FeatureReport) error {
				err := session.send(ctx, "/api/v1/agent/features", report)
				if errors.Is(err, ErrRequestRejected) {
					return errors.Join(features.ErrRejected, err)
				}
				return err
			}, logger)
		}()
	}
	go func() { workers.Wait(); close(featureDone) }()
	defer func() {
		cancel()
		select {
		case <-featureDone:
		case <-time.After(5 * time.Second):
			logger.Warn("feature shutdown deadline exceeded")
		}
	}()
	interval := c.HeartbeatInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	logger.Info("agent heartbeat loop started", "heartbeat_interval", interval.String())
	err = runHeartbeatLoop(ctx, interval, logger, session.pulse, waitContext, time.Now, retryJitter)
	if err == nil {
		logger.Info("agent heartbeat loop stopped")
	}
	return reconfigure.Load(), err
}
