package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"log/slog"
	"testing"
	"time"
)

type processActionAdapter struct{ calls int }

func (a *processActionAdapter) Collect(context.Context) (protocol.Processes, error) {
	return protocol.Processes{}, nil
}
func (a *processActionAdapter) Execute(_ context.Context, v protocol.ProcessAction) protocol.ProcessResult {
	a.calls++
	return protocol.ProcessResult{ID: v.ID, Outcome: "succeeded"}
}
func TestProcessActionResultRetriesNeverRepeatControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &processActionAdapter{}
	polls, sends := 0, 0
	runProcessActions(ctx, a, func(context.Context) (protocol.ProcessDispatch, error) {
		polls++
		if polls == 1 {
			return protocol.ProcessDispatch{Action: &protocol.ProcessAction{ID: "0123456789abcdef0123456789abcdef", PID: 1234, Start: "123456", Name: "fixture.exe", ExpiresAt: 1}}, nil
		}
		cancel()
		return protocol.ProcessDispatch{}, nil
	}, func(context.Context, protocol.ProcessResult) error {
		sends++
		if sends == 1 {
			return errors.New("outage")
		}
		return nil
	}, func(context.Context, time.Duration) bool { return true }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.calls != 1 || sends != 2 {
		t.Fatal("result delivery repeated execution", a.calls, sends)
	}
}
