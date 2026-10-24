package features

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type fakeModule struct {
	calls int
	fail  error
}

func (m *fakeModule) Capability() protocol.Capability {
	return protocol.Capability{Name: "inventory", Version: 1}
}
func (m *fakeModule) Collect(context.Context) (json.RawMessage, error) {
	m.calls++
	return json.RawMessage(`{"test":true}`), m.fail
}

func TestFailureDisabledUnsupportedAndRecoveryScheduling(t *testing.T) {
	for _, test := range []struct {
		name    string
		enabled bool
		err     error
		status  string
		calls   int
	}{
		{"ok", true, nil, "ok", 1}, {"failed", true, errors.New("private collector detail"), "failed", 1}, {"disabled", false, nil, "disabled", 0}, {"unsupported", true, ErrUnsupported, "unsupported", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := &fakeModule{fail: test.err}
			publications := 0
			run(context.Background(), Job{Module: m, Enabled: test.enabled, Interval: 15 * time.Minute}, func(_ context.Context, report protocol.FeatureReport) error {
				publications++
				if report.Status != test.status || (test.status != "ok" && len(report.Data) != 0) {
					t.Fatal("invalid collection outcome or error detail leaked")
				}
				return nil
			}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(_ context.Context, delay time.Duration) bool {
				if delay != 15*time.Minute {
					t.Fatal("wrong collection interval")
				}
				return false
			})
			if m.calls != test.calls || publications != 1 {
				t.Fatal("unexpected collection/publication count")
			}
		})
	}
}

func TestPublicationRetriesSameReportWithBoundedBackoffAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &fakeModule{}
	calls := 0
	delays := []time.Duration{}
	run(ctx, Job{Module: m, Enabled: true, Interval: 15 * time.Minute}, func(context.Context, protocol.FeatureReport) error { calls++; return errors.New("network unavailable") }, slog.New(slog.NewTextHandler(io.Discard, nil)), func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		if len(delays) == 10 {
			cancel()
			return false
		}
		return true
	})
	if m.calls != 1 || calls != 10 || delays[0] != time.Second || delays[9] != time.Minute {
		t.Fatal("retry growth/cap or report reuse failed")
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if wait(ctx, time.Hour) {
		t.Fatal("cancellation ignored")
	}
}

type sizedModule struct{ size int }

func (m sizedModule) Capability() protocol.Capability {
	return protocol.Capability{Name: "sized", Version: 1}
}
func (m sizedModule) Collect(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), m.size-2)) + `"`), nil
}
func TestPayloadLimitsAreExplicitAndBounded(t *testing.T) {
	for _, v := range []struct {
		size, limit int
		status      string
	}{{4096, 0, "ok"}, {4097, 0, "failed"}, {8192, 8192, "ok"}, {8193, 8192, "failed"}, {8192, 2*1024*1024 + 1, "failed"}} {
		run(context.Background(), Job{Module: sizedModule{v.size}, Enabled: true, Interval: time.Minute, MaxDataBytes: v.limit}, func(_ context.Context, r protocol.FeatureReport) error {
			if r.Status != v.status {
				t.Fatal("wrong payload bound", v, r.Status)
			}
			return nil
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(context.Context, time.Duration) bool { return false })
	}
}

func TestRejectedReportIsDroppedAndStaleReportRecollected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A rejected report is not resent; the module collects again next interval.
	m := &fakeModule{}
	publications := 0
	delays := []time.Duration{}
	run(context.Background(), Job{Module: m, Enabled: true, Interval: 15 * time.Minute}, func(context.Context, protocol.FeatureReport) error {
		publications++
		return ErrRejected
	}, logger, func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return len(delays) < 2
	})
	if m.calls != 2 || publications != 2 || delays[0] != 15*time.Minute {
		t.Fatal("rejected report was retried instead of re-collected", m.calls, publications, delays)
	}
	// A report that cannot be delivered for a whole interval is replaced by a
	// fresh collection rather than delivered late.
	m = &fakeModule{}
	waits := 0
	run(context.Background(), Job{Module: m, Enabled: true, Interval: time.Minute}, func(context.Context, protocol.FeatureReport) error {
		return errors.New("network unavailable")
	}, logger, func(context.Context, time.Duration) bool {
		waits++
		return waits < 12
	})
	if m.calls < 2 {
		t.Fatal("stale report was not re-collected", m.calls)
	}
}
