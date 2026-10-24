package sessions

import (
	"context"
	"encoding/json"
	"testing"
	"unsafe"
)

func TestWTSStructLayouts(t *testing.T) {
	if unsafe.Sizeof(wtsInfo{}) != 216 || unsafe.Offsetof(wtsInfo{}.ConnectTime) != 176 || unsafe.Sizeof(wtsClientAddressInfo{}) != 24 {
		t.Fatal("WTS structure layout does not match Windows", unsafe.Sizeof(wtsInfo{}), unsafe.Offsetof(wtsInfo{}.ConnectTime))
	}
}

// The native collector is read-only; this machine's sessions must form a
// valid report. A signed-in test session is reported when one exists.
func TestNativeSessions(t *testing.T) {
	b, err := Module{Collector: NewCollector()}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Sessions []map[string]any `json:"sessions"`
	}
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("invalid report")
	}
	for _, s := range v.Sessions {
		t.Logf("session %v: state %v, connection %v, logon set %v, idle %v", s["session_id"], s["state"], s["connection"], s["logon_at"] != float64(0), s["idle_seconds"])
	}
}
