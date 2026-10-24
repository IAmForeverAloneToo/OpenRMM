package localaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func sample() protocol.LocalAccounts {
	return protocol.LocalAccounts{
		Accounts: []protocol.LocalAccount{
			{Name: "Zed", SID: "S-1-5-21-1-2-3-1002", Enabled: true, PasswordLastSetAt: 1800000000},
			{Name: "Administrator", SID: "S-1-5-21-1-2-3-500", PasswordNeverExpires: true},
		},
		Groups: []protocol.LocalGroup{
			{Key: "administrators", Name: "Administrators", Members: []protocol.GroupMember{{Name: `PC\Zed`, SID: "S-1-5-21-1-2-3-1002", Kind: "user"}, {Name: `PC\Administrator`, SID: "S-1-5-21-1-2-3-500", Kind: "user"}}},
			{Key: "remote_desktop_users", Name: "Remote Desktop Users", Members: []protocol.GroupMember{}},
		},
	}
}

func TestLocalAccountsStrictSchema(t *testing.T) {
	good, _ := json.Marshal(sample())
	r, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: good})
	if err != nil {
		t.Fatal(err)
	}
	var v protocol.LocalAccounts
	if json.Unmarshal(r.Data, &v) != nil || v.Accounts[0].Name != "Administrator" || v.Groups[0].Members[0].SID != "S-1-5-21-1-2-3-1002" {
		t.Fatal("not normalised", v)
	}
	for name, raw := range map[string]string{
		"unknown field":   strings.Replace(string(good), `{"accounts"`, `{"device_id":"x","accounts"`, 1),
		"null field":      strings.Replace(string(good), `"full_name":""`, `"full_name":null`, 1),
		"bad sid":         strings.Replace(string(good), `"S-1-5-21-1-2-3-500"`, `"S-1-5-21-x"`, 1),
		"group order":     strings.Replace(strings.Replace(string(good), `"key":"administrators"`, `"key":"tmp"`, 1), `"key":"remote_desktop_users"`, `"key":"administrators"`, 1),
		"one group":       `{"accounts":[],"groups":[{"key":"administrators","name":"","members":[]}]}`,
		"duplicate sid":   strings.Replace(string(good), `"S-1-5-21-1-2-3-1002","enabled"`, `"S-1-5-21-1-2-3-500","enabled"`, 1),
		"bad kind":        strings.Replace(string(good), `"kind":"user"`, `"kind":"robot"`, 1),
		"control in name": strings.Replace(string(good), `"name":"Zed"`, `"name":"Z\u0001d"`, 1),
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(raw)}); !errors.Is(err, features.ErrReport) {
			t.Fatal(name, "accepted")
		}
	}
	if r, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: Capability.Name, Version: 2}, Status: "ok", Data: good}); err != nil || r.Status != "unsupported" {
		t.Fatal("newer version", err)
	}
}

type fixed struct{ v protocol.LocalAccounts }

func (f fixed) Collect(context.Context) (protocol.LocalAccounts, error) { return f.v, nil }

func TestModuleBoundsAccountsAndMembers(t *testing.T) {
	v := sample()
	v.Accounts = append(v.Accounts, protocol.LocalAccount{Name: "", SID: "S-1-5-21-9"}, v.Accounts[0])
	v.Groups[0].Members = append(v.Groups[0].Members, protocol.GroupMember{SID: "bad", Kind: "user"})
	v.Groups = v.Groups[:1] // a group the collector could not read is still reported, empty
	b, err := Module{Collector: fixed{v}}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out protocol.LocalAccounts
	if json.Unmarshal(b, &out) != nil || !Valid(out) || len(out.Accounts) != 2 || out.Skipped != 2 || out.Groups[0].Skipped != 1 || len(out.Groups) != 2 || len(out.Groups[1].Members) != 0 {
		t.Fatal("bounds", out)
	}
}
