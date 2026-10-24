package securitystatus

import (
	"encoding/json"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func report(v protocol.SecurityStatus) protocol.FeatureReport {
	b, _ := json.Marshal(v)
	return protocol.FeatureReport{Capability: Capability, Status: "ok", Data: b}
}

// Reports are checked strictly and summarized for the device list.
func TestNormalizeAndSummary(t *testing.T) {
	base := func() protocol.SecurityStatus {
		return protocol.SecurityStatus{
			BitLockerState: "available", DefenderState: "available",
			BitLocker: []protocol.BitLockerVolume{{Drive: "D:", Type: "fixed", Protection: "off", Conversion: "fully_decrypted"}, {Drive: "C:", Type: "os", Protection: "on", Conversion: "fully_encrypted", Percent: 100}},
			Defender:  &protocol.DefenderStatus{ServiceEnabled: true, AntivirusEnabled: true, RealTime: true, Mode: "normal", SignatureUpdated: "2026-10-22T18:40:20Z"},
			Antivirus: []protocol.AntivirusProduct{},
		}
	}
	if _, e := Normalize(report(base())); e != nil {
		t.Fatal(e)
	}
	bad := []func(*protocol.SecurityStatus){
		func(v *protocol.SecurityStatus) { v.BitLockerState = "on" },
		func(v *protocol.SecurityStatus) { v.Defender = nil },
		func(v *protocol.SecurityStatus) { v.DefenderState = "absent" },
		func(v *protocol.SecurityStatus) { v.BitLocker = nil },
		func(v *protocol.SecurityStatus) { v.BitLocker[0].Percent = 101 },
		func(v *protocol.SecurityStatus) { v.BitLocker[0].Drive = "C:\x1b[2J" },
		func(v *protocol.SecurityStatus) { v.Defender.SignatureUpdated = "yesterday" },
		func(v *protocol.SecurityStatus) { v.Antivirus = []protocol.AntivirusProduct{{Name: ""}} },
	}
	for i, f := range bad {
		v := base()
		f(&v)
		if _, e := Normalize(report(v)); e == nil {
			t.Fatal("accepted bad report", i)
		}
	}
	extra := report(base())
	extra.Data = append(extra.Data[:len(extra.Data)-1], []byte(`,"Extra":1}`)...)
	if _, e := Normalize(extra); e == nil {
		t.Fatal("accepted unknown field")
	}
	if r, e := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: Capability.Name, Version: 2}, Status: "ok", Data: []byte(`{}`)}); e != nil || r.Status != "unsupported" || r.Data != nil {
		t.Fatal("newer version", r, e)
	}

	cases := []struct {
		edit           func(*protocol.SecurityStatus)
		bitlocker, def string
	}{
		{func(v *protocol.SecurityStatus) {}, "on", "on"},
		{func(v *protocol.SecurityStatus) { v.BitLocker[1].Protection = "off" }, "suspended", "on"},
		{func(v *protocol.SecurityStatus) { v.BitLocker[1].Conversion = "encrypting" }, "encrypting", "on"},
		{func(v *protocol.SecurityStatus) { v.BitLocker[1].Conversion = "decrypting" }, "off", "on"},
		{func(v *protocol.SecurityStatus) { v.BitLocker = v.BitLocker[:1] }, "unknown", "on"},
		{func(v *protocol.SecurityStatus) { v.BitLockerState, v.BitLocker = "not_installed", nil }, "not_installed", "on"},
		{func(v *protocol.SecurityStatus) { v.Defender.RealTime = false }, "on", "real_time_off"},
		{func(v *protocol.SecurityStatus) { v.Defender.AntivirusEnabled = false }, "on", "off"},
		{func(v *protocol.SecurityStatus) { v.Defender.Mode = "passive" }, "on", "passive"},
		{func(v *protocol.SecurityStatus) {
			v.Defender.AntivirusEnabled, v.Antivirus = false, []protocol.AntivirusProduct{{Name: "Windows Defender"}, {Name: "Contoso AV", Enabled: true}}
		}, "on", "other_av"},
		{func(v *protocol.SecurityStatus) {
			v.Defender.AntivirusEnabled, v.Antivirus = false, []protocol.AntivirusProduct{{Name: "Contoso AV", Enabled: false}}
		}, "on", "off"},
		{func(v *protocol.SecurityStatus) { v.DefenderState, v.Defender = "absent", nil }, "on", "absent"},
		{func(v *protocol.SecurityStatus) { v.DefenderState, v.Defender = "unavailable", nil }, "on", "unknown"},
	}
	for i, c := range cases {
		v := base()
		c.edit(&v)
		if b, d := Summary(v); b != c.bitlocker || d != c.def {
			t.Fatal("summary", i, b, d)
		}
	}
}
