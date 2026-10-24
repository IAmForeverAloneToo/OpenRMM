package memory

import (
	"context"
	"errors"
	"testing"
	"unsafe"
)

func TestNativePhysicalMemoryAndLayout(t *testing.T) {
	var layout memoryStatusEx
	if unsafe.Sizeof(layout) != 64 || unsafe.Offsetof(layout.TotalPhys) != 8 || unsafe.Offsetof(layout.AvailPhys) != 16 || unsafe.Offsetof(layout.AvailExtendedVirtual) != 56 {
		t.Fatal("MEMORYSTATUSEX ABI layout mismatch")
	}
	got, err := NewCollector().Collect(context.Background())
	if err != nil || !Valid(got) {
		t.Fatalf("native RAM collector failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewCollector().Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}
