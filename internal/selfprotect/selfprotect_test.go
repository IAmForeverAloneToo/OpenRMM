package selfprotect

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// requireScripts skips source-tree consistency checks where the installer
// definition is not present (the container build context includes only Go
// code); scripts/check.ps1 runs them on the full tree.
func requireScripts(t *testing.T) {
	t.Helper()
	if _, e := os.Stat(filepath.Join("..", "..", "installer")); e != nil {
		t.Skip("installer definition is not in this build context")
	}
}

// The MSI definition is the source of truth for installed services: every
// installed OpenRMM service must be protected and every protected service must
// be installed by it.
func TestServicesMatchInstallers(t *testing.T) {
	requireScripts(t)
	b, e := os.ReadFile(filepath.Join("..", "..", "installer", "openrmm-agent.wxs"))
	if e != nil {
		t.Fatal("installer definition not found", e)
	}
	var installed []string
	for _, m := range regexp.MustCompile(`<ServiceInstall [^>]*Name="(OpenRMM[A-Za-z]+)"`).FindAllStringSubmatch(string(b), -1) {
		installed = append(installed, m[1])
	}
	sort.Strings(installed)
	want := Services()
	sort.Strings(want)
	if strings.Join(installed, ",") != strings.Join(want, ",") {
		t.Fatalf("installed services %v, protected %v", installed, want)
	}
}

// Every protected executable is an OpenRMM binary built from cmd/.
func TestExecutablesAreBuiltComponents(t *testing.T) {
	for _, x := range Executables() {
		if x == "openrmm-update-helper.exe" {
			continue // a copy of openrmm-agent.exe made at update time
		}
		dir := filepath.Join("..", "..", "cmd", strings.TrimSuffix(x, ".exe"))
		if s, e := os.Stat(dir); e != nil || !s.IsDir() {
			t.Fatalf("%s has no cmd directory", x)
		}
	}
	for _, x := range []string{"openrmm-agent.exe", "openrmm-update-helper.exe", "openrmm-desktop.exe", "OPENRMM-AGENT.EXE"} {
		if !Executable(x) {
			t.Fatal("component not protected", x)
		}
	}
	for _, x := range []string{"openrmm-server.exe", "openrmm-agent", "notepad.exe", ""} {
		if Executable(x) {
			t.Fatal("unexpected protection", x)
		}
	}
	for _, s := range []string{"OpenRMMAgent", "openrmmagent"} {
		if !Service(s) {
			t.Fatal("service not protected", s)
		}
	}
	if Service("Spooler") || Service("") {
		t.Fatal("unexpected service protection")
	}
	v := Services()
	v[0] = "changed"
	if !Service("OpenRMMAgent") {
		t.Fatal("shared list mutable")
	}
}
