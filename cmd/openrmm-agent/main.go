package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agent"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/isolation"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/logging"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
)

const usage = `OpenRMM agent console operations
Usage: openrmm-agent [flags]
  -server URL       HTTPS origin (default https://127.0.0.1:8443)
  -ca PATH          Trusted CA bundle (default .local/tls/ca.pem)
  -timeout DURATION Request deadline, 1s to 1m (default 5s)
  -ready            Check storage readiness at /readyz
  -enroll           Enroll a Windows x64 device; token JSON on stdin
  -connect          Authenticate using saved device credentials
  -renew            Renew credentials within seven days of expiry
  -release-isolation <code>
                    Lift network isolation with the release code shown in the
                    dashboard (break-glass; run as an administrator with the
                    agent's -state folder), then exit
  -run              Send heartbeats until Ctrl+C; renew credentials as needed
  -heartbeat-interval DURATION  Delay between heartbeats (default 30s; 1s to 5m)
  -inventory BOOL   Enable inventory (default true; use -inventory=false to disable)
  -inventory-interval DURATION Delay between collections (default 15m; 1m to 15m)
  -disk-space BOOL  Report system-drive disk space every 5m (default true)
  -memory BOOL      Report physical RAM every minute (default true)
  -cpu BOOL         Sample overall CPU usage every minute (default true)
  -uptime BOOL      Report Windows uptime/estimated boot every minute (default true)
  -terminal BOOL    Enable the interactive PowerShell terminal, as SYSTEM (default true)
  -scripts BOOL     Enable PowerShell scripts, as SYSTEM (default true)
  -processes BOOL   Report/control locally permitted Windows processes (default true)
  -software BOOL    Report machine-wide application registrations every 15m (default true)
  -sessions BOOL    Report signed-in Windows sessions every minute (default true)
  -response BOOL    Collect files as case evidence (default true)
  -local-accounts BOOL Report local accounts and Administrators / Remote Desktop
                    Users members every 15m (default true)
  -windows-updates BOOL Manage Windows updates through the optional local broker (default true)
  -event-logs BOOL  Enable on-demand System/Application log queries (default true)
  -services BOOL    Report/control locally permitted Windows services (default true)
  -state PATH       Private agent state directory (default .local/agent)
  -device-server URL Agent HTTPS origin (default https://127.0.0.1:8444)
  -log-level LEVEL  debug, info, warn, error (default info)
  -help             Show usage
Windows service operations: scripts/service.ps1 (see docs/WINDOWS-SERVICE.md).
Environment overrides and setup: see README.md.
`

func run() int {
	if len(os.Args) == 2 && os.Args[1] == "--script-worker" {
		return scripting.WorkerMain()
	}
	if len(os.Args) == 2 && os.Args[1] == windowsupdate.WorkerFlag {
		return windowsupdate.WorkerMain()
	}
	if len(os.Args) == 2 && os.Args[1] == agentupdate.HelperFlag {
		return agentupdate.HelperMain()
	}
	if handled, code := platformService(os.Args[1:]); handled {
		return code
	}
	c, err := config.LoadAgent(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(usage)
		return 0
	}
	if err != nil {
		logging.New(os.Stderr, slog.LevelInfo).Error("invalid agent configuration", "reason", err.Error())
		return 2
	}
	logger := logging.New(os.Stderr, c.LogLevel)
	if c.Service {
		logger.Error("service mode requires the Windows Service Control Manager; use scripts/service.ps1")
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if c.ReleaseIsolation != "" {
		m := &isolation.Manager{Dir: isolation.Dir(c.State), Enforcer: isolation.NewEnforcer()}
		if err := m.BreakGlass(c.ReleaseIsolation); err != nil {
			logger.Error("network isolation not released", "reason", err.Error())
			return 1
		}
		logger.Info("network isolation released; the agent reports it to the server when it reconnects")
		return 0
	}
	if c.Run {
		if err := agent.Run(ctx, c, logger); err != nil {
			logger.Error("agent stopped", "reason", err.Error())
			return 1
		}
		return 0
	}
	if c.Enroll || c.Connect || c.Renew {
		var id string
		if c.Enroll {
			token, readErr := readEnrollmentToken(os.Stdin)
			if readErr != nil {
				logger.Error("enrollment input rejected", "reason", readErr.Error())
				return 2
			}
			id, err = agent.Enroll(ctx, c, token)
		} else if c.Renew {
			id, err = agent.Renew(ctx, c)
		} else {
			id, err = agent.Connect(ctx, c)
		}
		if err != nil {
			logger.Error("device operation failed", "reason", err.Error())
			return 1
		}
		logger.Info("device operation completed", "device_id", id)
		return 0
	}
	if err := agent.Check(ctx, c); err != nil {
		logger.Error("health check failed", "reason", err.Error())
		return 1
	}
	logger.Info("server health check passed")
	return 0
}

func main() { os.Exit(run()) }

func readEnrollmentToken(input io.Reader) (string, error) {
	value, err := io.ReadAll(io.LimitReader(input, 257))
	if err != nil || len(value) > 256 {
		return "", errors.New("enrollment stdin must contain a bounded JSON token object")
	}
	var request struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || len(request.Token) != 43 {
		return "", errors.New("enrollment stdin must contain one JSON object with a valid token")
	}
	return request.Token, nil
}
