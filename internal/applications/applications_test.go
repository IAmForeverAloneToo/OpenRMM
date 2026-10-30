package applications

import (
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

func testDefinition() Definition {
	return Definition{Name: "Example", Version: "1.2.3", ProductCode: "{12A45678-1234-1234-1234-123456789ABC}", URL: "https://packages.example.invalid/Example.msi", SHA256: strings.Repeat("a", 64)}
}
func TestPackageValidationAndRunnerBindings(t *testing.T) {
	d := testDefinition()
	if !Valid(d) {
		t.Fatal("valid definition rejected")
	}
	for _, change := range []func(*Definition){func(d *Definition) { d.URL = "http://packages.example/a.msi" }, func(d *Definition) { d.URL = "https://user:pass@packages.example/a.msi" }, func(d *Definition) { d.URL += "?token=secret" }, func(d *Definition) { d.URL += "#fragment" }, func(d *Definition) { d.URL = "https://packages.example/a.exe" }, func(d *Definition) { d.Version = "256.1.0" }, func(d *Definition) { d.Version = "01.1.0" }, func(d *Definition) { d.Version = "1.2.65536" }, func(d *Definition) { d.Version = "1.2.3.4" }, func(d *Definition) { d.ProductCode = "..\\target" }, func(d *Definition) { d.SHA256 = strings.Repeat("A", 64) }} {
		bad := d
		change(&bad)
		if Valid(bad) {
			t.Fatal("invalid package accepted", bad)
		}
	}
	if !Newer("2.0.0", "1.255.65535") || Newer("1.0.0", "1.0.0") || Newer("0.255.0", "1.0.0") {
		t.Fatal("version ordering")
	}
	for _, verify := range []bool{false, true} {
		q := protocol.ScriptVersion{ID: strings.Repeat("b", 32), ScriptID: strings.Repeat("c", 32), Number: 1, Definition: Runner(d, verify)}
		q.Hash = scripting.Digest(q)
		if !scripting.VersionValid(q) {
			t.Fatal("invalid generated runner")
		}
		before := q.Hash
		d2 := d
		d2.SHA256 = strings.Repeat("d", 64)
		q.Definition = Runner(d2, verify)
		if scripting.Digest(q) == before {
			t.Fatal("approval did not bind payload hash")
		}
		if verify && q.Definition.RunAs != "restricted" || !verify && q.Definition.RunAs != "system" {
			t.Fatal("wrong identity")
		}
	}
}
func TestDeploymentReportPostconditions(t *testing.T) {
	d := testDefinition()
	zero := int32(0)
	r := Report{Format: "msi_v1", Operation: "install", Outcome: "verified", Reason: "verified", Observed: true, Products: []Product{{d.ProductCode, d.Version}}, Mutated: true, InstallerExit: &zero}
	if !ReportValid(r) || !PostconditionValid(d, r) {
		t.Fatal("valid result rejected")
	}
	bad := r
	bad.Products = []Product{}
	if PostconditionValid(d, bad) {
		t.Fatal("exit success inferred installed")
	}
	bad = r
	bad.InstallerExit = nil
	if ReportValid(bad) {
		t.Fatal("fabricated exit success")
	}
	bad = r
	bad.RestartRequired = true
	if ReportValid(bad) {
		t.Fatal("fabricated restart requirement")
	}
	bad = r
	bad.Outcome = "no_change"
	if ReportValid(bad) {
		t.Fatal("mutating no-op")
	}
	bad = r
	bad.Products = []Product{{"not-a-guid", d.Version}}
	if ReportValid(bad) {
		t.Fatal("invalid observation")
	}
	bad = r
	bad.Operation = "verify"
	if ReportValid(bad) {
		t.Fatal("read-only mutation")
	}
	bad = r
	bad.Outcome = "unknown"
	bad.Reason = "installer"
	bad.Observed = false
	bad.Products = []Product{}
	bad.InstallerExit = nil
	if !ReportValid(bad) {
		t.Fatal("honest unknown rejected")
	}
}

func TestPackageURL(t *testing.T) {
	d := testDefinition()
	for _, verify := range []bool{false, true} {
		if u, ok := PackageURL(Runner(d, verify).Body); !ok || u != d.URL {
			t.Fatal("package URL not found", u, ok)
		}
	}
	body := Runner(d, false).Body
	for _, other := range []string{"Write-Output hello", body + "\n# changed", strings.Replace(body, "FromBase64String('", "FromBase64String('!!", 1)} {
		if _, ok := PackageURL(other); ok {
			t.Fatal("not a generated runner, or damaged, but accepted")
		}
	}
}
