package cpu

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"testing"
	"time"
)

func TestNativeAggregateCPU(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	value, err := NewCollector().Collect(ctx)
	if errors.Is(err, features.ErrUnsupported) {
		t.Skip("multiple processor groups explicitly unsupported")
	}
	if err != nil || !Valid(value) {
		t.Fatalf("native CPU sampling failed: %v", err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := NewCollector().Collect(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
