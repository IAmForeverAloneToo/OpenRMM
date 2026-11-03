package yara

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fixtureSource is compiled by Windows PowerShell (the .NET Framework C#
// compiler) into a library whose metadata is known.
const fixtureSource = `using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
[assembly: Guid("2f5a8e1c-1b3d-4c6e-9a7b-0d1e2f3a4b5c")]
[assembly: System.Reflection.AssemblyVersion("1.2.3.4")]
namespace OpenRmm.Fixture {
  public interface IGreeter { string Greet(string name); }
  public class Greeter : IGreeter {
    private const string Prefix = "Hello, ";
    public string Greet(string name) { return Prefix + name + "!"; }
    public static int Add(int a, int b) { return a + b; }
    protected virtual List<string> Names(Dictionary<string, int> map, ref long total, int[] values, string[,] grid) { total = 0; return new List<string>(map.Keys); }
    public T First<T>(IList<T> items) { return items[0]; }
  }
  public sealed class Leaf : Greeter { }
  public abstract class Shape<TValue> { public abstract TValue Area(); internal class Inner { } }
  [StructLayout(LayoutKind.Explicit)] public struct Pair { [FieldOffset(0)] public int A; [FieldOffset(4)] public int B; }
  public static class Native {
    [DllImport("user32.dll")] public static extern int MessageBeep(uint type);
    public static string Banner() { return "openrmm-dotnet-fixture"; }
  }
}`

// compileFixture builds the library on Windows; it skips elsewhere.
func compileFixture(t *testing.T) []byte {
	if os.Getenv("SystemRoot") == "" {
		t.Skip("Windows only (the .NET Framework compiler)")
	}
	dir := t.TempDir()
	src, out := filepath.Join(dir, "fixture.cs"), filepath.Join(dir, "fixture.dll")
	if err := os.WriteFile(src, []byte(fixtureSource), 0600); err != nil {
		t.Fatal(err)
	}
	ps := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command",
		"Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath $env:FIXTURE_SRC) -OutputAssembly $env:FIXTURE_OUT -OutputType Library")
	cmd.Env = append(os.Environ(), "FIXTURE_SRC="+src, "FIXTURE_OUT="+out, "PSModulePath=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skip("cannot compile the fixture:", err, string(b))
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func wideText(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteByte(byte(c))
		b.WriteByte(0)
	}
	return b.String()
}

func TestDotnetFixture(t *testing.T) {
	data := compileFixture(t)
	p := parsePE(data, false, 0)
	n := parseDotnet(p)
	if n == nil {
		t.Fatal("no .NET metadata")
	}
	classes := map[string]netClass{}
	for _, c := range n.classes() {
		classes[c.fullname] = c
	}
	g, ok := classes["OpenRmm.Fixture.Greeter"]
	if !ok {
		t.Fatal(classes)
	}
	if g.visibility != "public" || g.kind != "class" || g.abstract || g.sealed || strings.Join(g.bases, ",") != "System.Object,OpenRmm.Fixture.IGreeter" {
		t.Errorf("Greeter: %+v", g)
	}
	methods := map[string]netMethod{}
	for _, m := range g.methods {
		methods[m.name] = m
	}
	sig := func(m netMethod) string {
		var ps []string
		for _, p := range m.params {
			ps = append(ps, p.typ+" "+p.name)
		}
		return m.visibility + " " + m.ret + " " + m.name + "(" + strings.Join(ps, ", ") + ")"
	}
	for name, want := range map[string]string{
		"Greet": "public string Greet(string name)",
		"Add":   "public int Add(int a, int b)",
		"Names": "protected System.Collections.Generic.List<string> Names(System.Collections.Generic.Dictionary<string,int> map, ref long total, int[] values, string[,] grid)",
		"First": "public T First(System.Collections.Generic.IList<T> items)",
		".ctor": "public void .ctor()",
	} {
		if got := sig(methods[name]); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if !methods["Add"].static || !methods["Names"].virtual || strings.Join(methods["First"].generics, ",") != "T" || !methods["Greet"].virtual {
		t.Errorf("method flags: %+v", methods)
	}
	if c := classes["OpenRmm.Fixture.IGreeter"]; c.kind != "interface" || !c.abstract {
		t.Errorf("IGreeter: %+v", c)
	}
	if c := classes["OpenRmm.Fixture.Leaf"]; !c.sealed || strings.Join(c.bases, ",") != "OpenRmm.Fixture.Greeter" {
		t.Errorf("Leaf: %+v", c)
	}
	shape := classes["OpenRmm.Fixture.Shape`1"]
	if !shape.abstract || strings.Join(shape.generics, ",") != "TValue" || len(shape.methods) < 1 || shape.methods[0].ret != "TValue" || !shape.methods[0].abstract {
		t.Errorf("Shape: %+v", shape)
	}
	if c, ok := classes["OpenRmm.Fixture.Shape`1.Inner"]; !ok || c.visibility != "internal" {
		t.Errorf("nested class: %+v %v", c, ok)
	}
	if c := classes["OpenRmm.Fixture.Native"]; !c.abstract || !c.sealed {
		t.Errorf("static class: %+v", c)
	}

	got := scanText(t, `import "dotnet"
rule header { condition: dotnet.is_dotnet and dotnet.version == "v4.0.30319" and dotnet.module_name == "fixture.dll"
  and dotnet.assembly.name == "fixture" and dotnet.assembly.version.major == 1 and dotnet.assembly.version.revision_number == 4
  and dotnet.typelib == "2f5a8e1c-1b3d-4c6e-9a7b-0d1e2f3a4b5c" and dotnet.number_of_guids == 1 }
rule refs { condition: for any r in dotnet.assembly_refs : ( r.name == "mscorlib" and r.version.major == 4 )
  and for any m in dotnet.modulerefs : ( m == "user32.dll" ) }
rule streams { condition: dotnet.number_of_streams == 5 and for any s in dotnet.streams : ( s.name == "#Strings" and s.size > 0 ) }
rule texts { condition: for any s in dotnet.user_strings : ( s == "`+wideText("openrmm-dotnet-fixture")+`" )
  and for any c in dotnet.constants : ( c == "`+wideText("Hello, ")+`" ) and dotnet.number_of_field_offsets == 2 and dotnet.field_offsets[1] == 4 }
rule classes { condition: for any c in dotnet.classes : ( c.fullname == "OpenRmm.Fixture.Greeter"
  and for any m in c.methods : ( m.name == "Names" and m.number_of_parameters == 4 and m.parameters[2].type == "int[]" and m.visibility == "protected" ) ) }
`, string(data))
	if strings.Join(got, ",") != "header,refs,streams,texts,classes" {
		t.Fatal(got)
	}
	// A native PE is not .NET.
	if got := scanText(t, `import "dotnet" rule r { condition: not dotnet.is_dotnet and not defined dotnet.version }`, string(buildFixture())); len(got) != 1 {
		t.Fatal("native PE", got)
	}
}

// On a large real assembly (System.dll of .NET Framework), the classes
// agree in number with .NET's own reflection, and every one has a name.
func TestDotnetSystemAssembly(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" || testing.Short() {
		t.Skip("Windows, not in short mode")
	}
	path := filepath.Join(root, "Microsoft.NET", "assembly", "GAC_MSIL", "System", "v4.0_4.0.0.0__b77a5c561934e089", "System.dll")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip(err)
	}
	n := parseDotnet(parsePE(data, false, 0))
	if n == nil {
		t.Fatal("no metadata")
	}
	classes := n.classes()
	methods := 0
	for _, c := range classes {
		if c.name == "" || c.fullname == "" {
			t.Fatalf("unnamed class %+v", c)
		}
		methods += len(c.methods)
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "[System.Reflection.Assembly]::LoadFrom($env:ASSEMBLY).GetTypes().Count")
	cmd.Env = append(os.Environ(), "ASSEMBLY="+path, "PSModulePath=")
	out, err := cmd.Output()
	if err != nil {
		t.Skip("reflection unavailable:", err)
	}
	want, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	if len(classes) != want {
		t.Errorf("%d classes, reflection finds %d", len(classes), want)
	}
	t.Logf("System.dll: %d classes, %d methods, %d user strings", len(classes), methods, len(n.userStrings()))
}

// Damaged copies of a real assembly never panic and stay quick: changed
// bytes in the metadata, and truncations.
func TestDotnetDamaged(t *testing.T) {
	data := compileFixture(t)
	n := parseDotnet(parsePE(data, false, 0))
	if n == nil {
		t.Fatal("no metadata")
	}
	start, end := int(n.root), len(data)
	seed := uint32(3)
	run := func(c []byte) {
		if m := parseDotnet(parsePE(c, false, 0)); m != nil {
			m.classes()
			m.userStrings()
			m.resources()
			m.typelib()
			m.assemblyRefs()
			m.constants()
			m.guidList()
		}
	}
	for range 5000 {
		c := append([]byte(nil), data...)
		for range 1 + seed%6 {
			seed = seed*1664525 + 1013904223
			c[start+int(seed>>8)%(end-start)] = byte(seed >> 24)
		}
		run(c)
	}
	for cut := start; cut < end; cut += 7 {
		run(data[:cut])
	}
}
