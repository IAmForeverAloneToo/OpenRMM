package winservices

import (
	"context"
	"testing"
)

func TestNativeServiceListingAndCancellation(t *testing.T) {
	v, e := NewAdapter().Collect(context.Background())
	if e != nil || !Valid(v) || len(v.Items) == 0 {
		t.Fatal("native service enumeration failed", e)
	}
	for _, s := range v.Items {
		if !Manageable(s.Name) && (s.CanStart || s.CanStop) {
			t.Fatal("OpenRMM service offered a control", s.Name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := NewAdapter().Collect(ctx); e == nil {
		t.Fatal("cancelled enumeration succeeded")
	}
}
