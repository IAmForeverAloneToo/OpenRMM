package securitystatus

import (
	"context"
	"testing"
	"time"
)

// The native collector reads BitLocker, Defender and Security
// Center on the local machine within the module's time limit, and the report is valid.
func TestNativeSecurityStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	start := time.Now()
	v, e := NewCollector().Collect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("%s: %+v defender %+v", time.Since(start), v, v.Defender)
	if !Valid(v) {
		t.Fatalf("invalid report %+v", v)
	}
	b, d := Summary(v)
	t.Log("summary", b, d)
	if v.DefenderState == "available" && d == "unknown" {
		t.Fatal("defender summary")
	}
}
