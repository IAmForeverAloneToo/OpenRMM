package uptime

import (
	"context"
	"errors"
	"testing"
)

func TestNativeWindowsUptimeAndCancellation(t *testing.T) {
	first, err := NewCollector().Collect(context.Background())
	if err != nil || !Valid(first) {
		t.Fatalf("native uptime failed: %v", err)
	}
	second, err := NewCollector().Collect(context.Background())
	if err != nil || !Valid(second) || second.UptimeSeconds < first.UptimeSeconds {
		t.Fatal("native uptime went backwards")
	}
	if diff := second.EstimatedBootAt - first.EstimatedBootAt; diff < -1 || diff > 1 {
		t.Fatal("boot estimate unstable across immediate native reads")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewCollector().Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
