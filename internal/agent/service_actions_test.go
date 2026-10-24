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

type actionAdapter struct{ calls int }

func (a *actionAdapter) Collect(context.Context) (protocol.Services, error) {
	return protocol.Services{}, nil
}
func (a *actionAdapter) Execute(_ context.Context, v protocol.ServiceAction) protocol.ServiceResult {
	a.calls++
	return protocol.ServiceResult{ID: v.ID, Outcome: "succeeded", State: "running"}
}
func TestActionResultRetriesNeverRepeatControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &actionAdapter{}
	polls, sends := 0, 0
	runServiceActions(ctx, a, func(context.Context) (protocol.ServiceDispatch, error) {
		polls++
		if polls == 1 {
			return protocol.ServiceDispatch{Action: &protocol.ServiceAction{ID: "0123456789abcdef0123456789abcdef", Service: "Example", Action: "restart", ExpiresAt: 1}}, nil
		}
		cancel()
		return protocol.ServiceDispatch{}, nil
	}, func(context.Context, protocol.ServiceResult) error {
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

// R7: neither a malformed dispatch nor a server rejection ends the worker; it
// discards what it cannot trust, backs off, and keeps serving later dispatches.
func TestActionWorkerSurvivesInvalidDispatchAndRejections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &actionAdapter{}
	polls := 0
	var delays []time.Duration
	responses := []func() (protocol.ServiceDispatch, error){
		func() (protocol.ServiceDispatch, error) {
			return protocol.ServiceDispatch{Action: &protocol.ServiceAction{ID: "not-an-id", Service: "Example", Action: "restart", ExpiresAt: 1}}, nil
		},
		func() (protocol.ServiceDispatch, error) { return protocol.ServiceDispatch{}, ErrRequestRejected },
		func() (protocol.ServiceDispatch, error) { return protocol.ServiceDispatch{}, ErrDeviceRejected },
		func() (protocol.ServiceDispatch, error) { return protocol.ServiceDispatch{}, ErrDeviceRevoked },
		func() (protocol.ServiceDispatch, error) {
			return protocol.ServiceDispatch{Action: &protocol.ServiceAction{ID: "0123456789abcdef0123456789abcdef", Service: "Example", Action: "restart", ExpiresAt: 1}}, nil
		},
	}
	runServiceActions(ctx, a, func(context.Context) (protocol.ServiceDispatch, error) {
		polls++
		if polls > len(responses) {
			cancel()
			return protocol.ServiceDispatch{}, nil
		}
		return responses[polls-1]()
	}, func(context.Context, protocol.ServiceResult) error { return nil }, func(_ context.Context, d time.Duration) bool {
		delays = append(delays, d)
		return true
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if a.calls != 1 || polls != len(responses)+1 {
		t.Fatal("worker stopped early or executed an invalid dispatch", a.calls, polls)
	}
	if len(delays) < 4 || delays[0] != 5*time.Second || delays[1] != 10*time.Second || delays[2] != 20*time.Second || delays[3] != time.Minute {
		t.Fatal("unexpected back-off after invalid dispatch, rejections and revocation", delays)
	}
}

func TestPacerSchedule(t *testing.T) {
	var p pacer
	if d := p.next(nil, 5*time.Second); d != 5*time.Second {
		t.Fatal("normal interval", d)
	}
	var last time.Duration
	for range 12 {
		last = p.next(ErrRequestRejected, 5*time.Second)
	}
	if last != 5*time.Minute {
		t.Fatal("rejection cap", last)
	}
	p = pacer{}
	for range 12 {
		last = p.next(errors.New("network"), 5*time.Second)
	}
	if last != time.Minute || p.next(ErrDeviceThrottled, 5*time.Second) != time.Minute || p.next(nil, 5*time.Second) != 5*time.Second || p.backoff != 0 {
		t.Fatal("transient cap, throttle or reset", last)
	}
}
