package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestYaraRuleSets(t *testing.T) {
	ctx := context.Background()
	s, _, _, now := evidenceFixture(t)
	const v1 = `rule example_dumper { strings: $a = "dumpcreds::allsessions" condition: $a }`
	set, e := s.SaveYaraRuleSet(ctx, "", " Tools ", v1, "owner", now)
	if e != nil || set.Name != "Tools" || set.Version != 1 || set.Rules != 1 || set.Source != v1 || len(set.SHA256) != 64 {
		t.Fatalf("%+v %v", set, e)
	}
	// Rules that do not compile are refused with the reason.
	if _, e := s.SaveYaraRuleSet(ctx, "", "Broken", `rule x { condition: $nope }`, "owner", now); !errors.Is(e, ErrYaraRules) || !strings.Contains(e.Error(), "undefined string") {
		t.Fatal(e)
	}
	if _, e := s.SaveYaraRuleSet(ctx, "", "tools", v1, "owner", now); !errors.Is(e, ErrYaraSet) {
		t.Fatal("duplicate name accepted", e)
	}
	// A new version.
	v2 := v1 + "\nrule second { condition: filesize < 10 }"
	set, e = s.SaveYaraRuleSet(ctx, set.ID, "Tools", v2, "owner", now)
	if e != nil || set.Version != 2 || set.Rules != 2 {
		t.Fatalf("%+v %v", set, e)
	}
	list, _ := s.YaraRuleSets(ctx)
	if len(list) != 1 || list[0].Source != "" || list[0].Version != 2 {
		t.Fatalf("%+v", list)
	}
	if got, e := s.YaraRuleSetNamed(ctx, "TOOLS"); e != nil || got.Source != v2 {
		t.Fatal(got, e)
	}
	// Withdrawn: gone from use, name free again, versions kept.
	if e := s.WithdrawYaraRuleSet(ctx, set.ID, "owner", now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.YaraRuleSet(ctx, set.ID); !errors.Is(e, ErrYaraSet) {
		t.Fatal("withdrawn set readable", e)
	}
	if _, e := s.SaveYaraRuleSet(ctx, "", "Tools", v1, "owner", now); e != nil {
		t.Fatal("name of a withdrawn set not reusable", e)
	}
	var kept int
	s.db.QueryRow(`SELECT COUNT(*) FROM yara_rule_versions WHERE set_id=?`, set.ID).Scan(&kept)
	if kept != 2 {
		t.Fatal("versions", kept)
	}
	// Each change is in the audit log.
	var audited int
	s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action LIKE 'yara_rule_set_%'`).Scan(&audited)
	if audited != 4 {
		t.Fatal("audit", audited)
	}
}
