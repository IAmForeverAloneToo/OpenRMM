package agentservice

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"golang.org/x/sys/windows/svc"
)

func TestServiceControlsCancelAndReportCleanStop(t *testing.T) {
	dir := t.TempDir()
	started := make(chan struct{})
	cancelled := make(chan struct{})
	h := &handler{config: config.Agent{Service: true, LogDirectory: dir}, run: func(ctx context.Context, _ config.Agent, _ *slog.Logger) error {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil
	}}
	requests := make(chan svc.ChangeRequest, 3)
	changes := make(chan svc.Status, 10)
	done := make(chan uint32, 1)
	go func() { _, code := h.Execute(nil, requests, changes); done <- code }()
	if (<-changes).State != svc.StartPending || (<-changes).State != svc.Running {
		t.Fatal("bad startup status")
	}
	<-started
	requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
	if status := <-changes; status.State != svc.Running || status.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Fatal("bad interrogation status")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if (<-changes).State != svc.StopPending {
		t.Fatal("missing graceful stop status")
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal("unclean exit")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stop failed to cancel active loop")
	}
	<-cancelled
	log, err := os.ReadFile(filepath.Join(dir, "agent.log"))
	if err != nil || !strings.Contains(string(log), "stopped cleanly") {
		t.Fatal("missing clean shutdown log")
	}
}

func TestServiceFailsClosed(t *testing.T) {
	for _, startupErr := range []error{nil, errors.New("invalid configuration")} {
		h := &handler{config: config.Agent{}, startupErr: startupErr, run: func(context.Context, config.Agent, *slog.Logger) error {
			t.Fatal("invalid startup ran agent")
			return nil
		}}
		if _, code := h.Execute(nil, nil, make(chan svc.Status, 2)); code == 0 {
			t.Fatal("invalid configuration started")
		}
	}
	h := &handler{config: config.Agent{Service: true, LogDirectory: t.TempDir()}, run: func(context.Context, config.Agent, *slog.Logger) error { return errors.New("credentials rejected") }}
	if _, code := h.Execute(nil, nil, make(chan svc.Status, 2)); code == 0 {
		t.Fatal("terminal failure reported success")
	}
}
