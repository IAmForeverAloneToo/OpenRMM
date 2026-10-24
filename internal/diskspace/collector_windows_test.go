package diskspace

import (
	"context"
	"errors"
	"testing"
)

func TestNativeSystemDrive(t *testing.T) {
	got, err := NewCollector().Collect(context.Background())
	if err != nil || !Valid(got) {
		t.Fatalf("native collector failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewCollector().Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
