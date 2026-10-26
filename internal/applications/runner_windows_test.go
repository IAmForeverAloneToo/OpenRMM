package applications

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--script-worker" {
		os.Exit(scripting.WorkerMain())
	}
	os.Exit(m.Run())
}

func TestNativeReadOnlyMSIRegistrationAndLiteralMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Windows PowerShell; timing-sensitive, run without -short on a real machine")
	}
	d := testDefinition()
	d.Name = "literal '; throw 'injection'; # $(data) 日本語"
	d.ProductCode = "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
	q := protocol.ScriptJob{ID: strings.Repeat("a", 32), Version: protocol.ScriptVersion{ID: strings.Repeat("b", 32), ScriptID: strings.Repeat("c", 32), Number: 1, Definition: Runner(d, true)}, Arguments: map[string]string{"Operation": "verify", "KnownProducts": `["{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"]`}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	q.Version.Hash = scripting.Digest(q.Version)
	r := scripting.RunContained(context.Background(), t.TempDir(), q)
	var report Report
	if r.Outcome != "succeeded" || r.Truncated || scripting.Decode([]byte(strings.TrimSpace(r.Stdout)), &report) != nil || !ReportValid(report) || report.Outcome != "verified" || !report.Observed || report.Mutated || len(report.Products) != 0 {
		t.Fatalf("native read-only contract failed: %+v / %+v", r, report)
	}
	q.ID = strings.Repeat("d", 32)
	q.Arguments["Operation"] = "install"
	r = scripting.RunContained(context.Background(), t.TempDir(), q)
	if r.Outcome != "failed" || r.ExitCode == nil || *r.ExitCode != 91 {
		t.Fatal("verification runner permitted mutation", r)
	}
}

func TestNativeMSIIdentityBeforeExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("starts Windows PowerShell; timing-sensitive, run without -short on a real machine")
	}
	d := testDefinition()
	// A property-only inert MSI database, created in the private test workspace.
	// It is opened read-only by the production inspector and never installed.
	prefix := strings.SplitN(Runner(d, false).Body, "# Begin lifecycle", 2)[0]
	body := prefix + `
$file=Join-Path $PSScriptRoot 'inert.msi'
$maker=New-Object -ComObject WindowsInstaller.Installer
$database=$maker.OpenDatabase($file,3)
foreach($sql in @('CREATE TABLE ` + "`Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) LOCALIZABLE PRIMARY KEY `Property`)" + `',('INSERT INTO ` + "`Property` (`Property`,`Value`) VALUES (''ProductCode'',''" + `'+$package.product_code+''')'),('INSERT INTO ` + "`Property` (`Property`,`Value`) VALUES (''ProductVersion'',''" + `'+$package.version+''')'))) {
    $view=$database.OpenView($sql);$view.Execute();$view.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
}
$database.Commit();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($maker)
Assert-PackageIdentity $file
$package.product_code='{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}'
$rejected=$false
try { Assert-PackageIdentity $file } catch { $rejected=$true }
if (-not $rejected) { throw 'Mismatched installer identity accepted' }
Write-Output 'identity checked; mismatch rejected'
`
	q := protocol.ScriptJob{ID: strings.Repeat("a", 32), Version: protocol.ScriptVersion{ID: strings.Repeat("b", 32), ScriptID: strings.Repeat("c", 32), Number: 1, Definition: protocol.ScriptDefinition{Name: "Native inert MSI inspector", Body: body, Parameters: []protocol.ScriptParameter{}, RunAs: "restricted", Timeout: 30}}, Arguments: map[string]string{}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	q.Version.Hash = scripting.Digest(q.Version)
	r := scripting.RunContained(context.Background(), t.TempDir(), q)
	if r.Outcome != "succeeded" || strings.TrimSpace(r.Stdout) != "identity checked; mismatch rejected" {
		t.Fatalf("native metadata inspector failed: %+v", r)
	}
}
