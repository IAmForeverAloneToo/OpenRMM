package software

import (
	"context"
	"golang.org/x/sys/windows/registry"
	"strings"
	"testing"
	"time"
)

func TestNativeReadOnlySoftware(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, e := NewCollector().Collect(ctx)
	if e != nil {
		t.Fatal("native software collection failed:", e)
	}
	if !Valid(v) {
		t.Fatal("invalid native inventory")
	}
	users := 0
	for _, x := range v.Entries {
		if x.View == "user" {
			users++
		}
	}
	t.Logf("Collected %d bounded registrations, %d per-user from %+v", len(v.Entries), users, v.Users)
}
func TestNativeRegistryMetadataBounds(t *testing.T) {
	path := `Software\OpenRMM-Software-Test-` + t.Name()
	key, exists, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal(e)
	}
	if exists {
		key.Close()
		t.Fatal("existing fixture requires inspection")
	}
	defer func() {
		key.Close()
		if e := registry.DeleteKey(registry.CURRENT_USER, path); e != nil {
			t.Error(e)
		}
	}()
	for _, v := range []struct{ name, value string }{{"DisplayName", "Example <app>"}, {"DisplayVersion", "1.0"}, {"Publisher", "Example"}} {
		if e = key.SetStringValue(v.name, v.value); e != nil {
			t.Fatal(e)
		}
	}
	a, e := readEntry(key, "fixed-identity", "64")
	if e != nil || a == nil || a.Name != "Example <app>" {
		t.Fatal("native values not read", e)
	}
	b, e := readEntry(key, "fixed-identity", "32")
	if e != nil || b == nil || a.ID == b.ID {
		t.Fatal("registry views merged")
	}
	if e = key.SetDWordValue("SystemComponent", 1); e != nil {
		t.Fatal(e)
	}
	if v, e := readEntry(key, "fixed-identity", "64"); e != nil || v != nil {
		t.Fatal("hidden component collected")
	}
	key.DeleteValue("SystemComponent")
	if e = key.SetBinaryValue("DisplayVersion", []byte{1, 2}); e != nil {
		t.Fatal(e)
	}
	if _, e = readEntry(key, "fixed-identity", "64"); e == nil {
		t.Fatal("binary version accepted")
	}
	if e = key.SetStringValue("DisplayVersion", strings.Repeat("x", 3000)); e != nil {
		t.Fatal(e)
	}
	if _, e = readEntry(key, "fixed-identity", "64"); e == nil {
		t.Fatal("oversized value accepted")
	}
	// Collect counts these per-registration failures instead of failing.
	if e = key.SetStringValue("DisplayVersion", "1.0"); e != nil {
		t.Fatal(e)
	}
	if e = key.SetStringValue("DisplayName", "Example\x01app"); e != nil {
		t.Fatal(e)
	}
	if _, e = readEntry(key, "fixed-identity", "64"); e == nil {
		t.Fatal("control character accepted")
	}
}
