package agentservice

import (
	"context"
	"errors"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agent"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/logging"
)

const Name = "OpenRMMAgent"

type handler struct {
	config     config.Agent
	startupErr error
	run        func(context.Context, config.Agent, *slog.Logger) error
}

// Dispatch registers with SCM even when configuration is invalid, so SCM sees a
// clean startup failure rather than waiting for its connection timeout.
func Dispatch(c config.Agent, configErr error) error {
	return svc.Run(Name, &handler{config: c, startupErr: configErr, run: agent.Run})
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending, WaitHint: 10000}
	if h.startupErr != nil || !h.config.Service {
		return false, 87
	}
	output, err := OpenLog(h.config.LogDirectory)
	if err != nil {
		return false, 5
	}
	defer output.Close()
	logger := logging.New(output, h.config.LogLevel)
	if err := configureSelf(); err != nil {
		logger.Warn("cannot set delayed start and crash recovery for the agent service")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx, h.config, logger) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	logger.Info("Windows service started")
	changes <- current
	for {
		select {
		case err := <-done:
			if err != nil {
				logger.Error("agent stopped; operator action required", "reason", err.Error())
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancel()
				return true, 2
			}
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown:
				current = svc.Status{State: svc.StopPending, WaitHint: 10000, CheckPoint: 1}
				changes <- current
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						logger.Warn("agent returned an error during shutdown")
					}
					logger.Info("Windows service stopped cleanly")
					return false, 0
				case <-time.After(8 * time.Second):
					logger.Error("Windows service shutdown deadline exceeded")
					return true, 2
				}
			}
		}
	}
}

// configureSelf applies what the MSI cannot express with wixl:
// delayed automatic start and bounded crash recovery (restart after 1 and
// 2 minutes, then stop; reset after a day). Controlled exits do not restart.
func configureSelf() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	delayed := windows.SERVICE_DELAYED_AUTO_START_INFO{IsDelayedAutoStartUp: 1}
	if err = windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&delayed))); err != nil {
		return err
	}
	if err = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Minute}, {Type: mgr.ServiceRestart, Delay: 2 * time.Minute}, {Type: mgr.NoAction}}, 86400); err != nil {
		return err
	}
	return s.SetRecoveryActionsOnNonCrashFailures(false)
}
