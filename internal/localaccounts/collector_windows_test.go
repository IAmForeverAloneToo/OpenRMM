package localaccounts

import (
	"context"
	"encoding/json"
	"testing"
	"unsafe"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestNetAPIStructLayouts(t *testing.T) {
	if unsafe.Sizeof(userInfo3{}) != 184 || unsafe.Offsetof(userInfo3{}.UserID) != 152 || unsafe.Sizeof(localGroupMembersInfo2{}) != 24 {
		t.Fatal("NetAPI structure layout does not match Windows", unsafe.Sizeof(userInfo3{}), unsafe.Sizeof(localGroupMembersInfo2{}))
	}
}

// The native collector is read-only; this machine's accounts and privileged
// groups must form a valid report with at least one administrator.
func TestNativeLocalAccounts(t *testing.T) {
	b, err := Module{Collector: NewCollector()}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var v protocol.LocalAccounts
	if json.Unmarshal(b, &v) != nil || !Valid(v) || len(v.Accounts) == 0 || len(v.Groups[0].Members) == 0 {
		t.Fatal("invalid report")
	}
	for _, a := range v.Accounts {
		t.Logf("account: enabled %v, password set %v, last logon %v", a.Enabled, a.PasswordLastSetAt > 0, a.LastLogonAt > 0)
	}
	for _, g := range v.Groups {
		t.Logf("group %s (%s): %d members, skipped %d", g.Key, g.Name, len(g.Members), g.Skipped)
	}
}
