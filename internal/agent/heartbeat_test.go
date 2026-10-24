package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHeartbeatBackoffCapsResetsAndSuppressesRepeatedLogs(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	now := time.Unix(1800000000, 0)
	var delays []time.Duration
	calls := 0
	err := runHeartbeatLoop(ctx, 30*time.Second, logger, func(context.Context) error {
		calls++
		if calls == 9 {
			return nil
		}
		return errors.New("untrusted detail must never enter loop logs")
	}, func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		now = now.Add(delay)
		return len(delays) < 10
	}, func() time.Time { return now }, func(base time.Duration) time.Duration { return base })
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute, 30 * time.Second, time.Second}
	if !reflect.DeepEqual(delays, want) {
		t.Fatalf("unexpected retry schedule: %v", delays)
	}
	if strings.Count(logs.String(), "heartbeat unavailable") != 2 || strings.Count(logs.String(), "agent connected;") != 1 || strings.Contains(logs.String(), "untrusted detail") {
		t.Fatal("transition logs were noisy or exposed raw errors")
	}
}
func TestHeartbeatRetriesRejectionsAndPausesHourlyOnRevocation(t *testing.T) {
	// R1: only cancellation ends the loop. Unexpected rejections (for example a
	// proxy's 4xx) back off up to five minutes; a confirmed revocation re-checks
	// hourly; each is logged without raw error detail from the network.
	for _, test := range []struct {
		err   error
		last  time.Duration
		notes string
	}{
		{ErrDeviceRejected, 5 * time.Minute, "rejected by the server"},
		{ErrRequestRejected, 5 * time.Minute, "rejected by the server"},
		{ErrDeviceRevoked, time.Hour, "revoked by an administrator"},
	} {
		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))
		var delays []time.Duration
		err := runHeartbeatLoop(context.Background(), 30*time.Second, logger, func(context.Context) error { return test.err }, func(_ context.Context, d time.Duration) bool {
			delays = append(delays, d)
			return len(delays) < 12
		}, time.Now, func(base time.Duration) time.Duration { return base })
		if err != nil || len(delays) != 12 || delays[11] != test.last || !strings.Contains(logs.String(), test.notes) {
			t.Fatal("rejection stopped the loop or used the wrong schedule", test.err, err, delays)
		}
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitContext(ctx, time.Hour) {
		t.Fatal("cancellation did not interrupt delay")
	}
	called := false
	if err := runHeartbeatLoop(ctx, time.Second, logger, func(context.Context) error { called = true; return nil }, waitContext, time.Now, retryJitter); err != nil || called {
		t.Fatal("canceled loop issued a request")
	}
}
func TestRetryJitterBoundsAndThrottleMinimum(t *testing.T) {
	for _, base := range []time.Duration{time.Second, 2 * time.Second, time.Minute} {
		seen := map[time.Duration]bool{}
		for index := 0; index < 20; index++ {
			delay := retryJitter(base)
			if delay < base/2 || delay > base {
				t.Fatal("retry outside jitter bounds")
			}
			seen[delay] = true
		}
		if len(seen) < 2 {
			t.Fatal("retry timing did not vary")
		}
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	var delay time.Duration
	if err := runHeartbeatLoop(context.Background(), time.Second, logger, func(context.Context) error { return ErrDeviceThrottled }, func(_ context.Context, d time.Duration) bool { delay = d; return false }, time.Now, func(time.Duration) time.Duration { return time.Millisecond }); err != nil || delay < time.Minute {
		t.Fatal("server throttle was retried too soon")
	}
}
