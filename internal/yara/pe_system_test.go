package yara

import (
	"bytes"
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// On Windows, the parser agrees with Go's debug/pe (used here only, as a
// reference) on Windows' own programs: headers, sections and the functions
// imported by name.
func TestPESystemFiles(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("Windows only")
	}
	for _, name := range []string{"notepad.exe", "kernel32.dll", "ntdll.dll", "ws2_32.dll", "oleaut32.dll", "cmd.exe"} {
		data, err := os.ReadFile(filepath.Join(root, "System32", name))
		if err != nil {
			t.Fatal(err)
		}
		ref, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(name, err)
		}
		p := parsePE(data, false, 0)
		if p == nil {
			t.Fatal(name, "not parsed")
		}
		opt := ref.OptionalHeader.(*pe.OptionalHeader64)
		if p.machine != ref.Machine || int(p.numSections) != len(ref.Sections) || p.timestamp != ref.TimeDateStamp ||
			p.entry != opt.AddressOfEntryPoint || p.imageBase != opt.ImageBase || p.sizeImage != opt.SizeOfImage || p.checksum != opt.CheckSum {
			t.Errorf("%s: headers differ", name)
		}
		for i, s := range ref.Sections {
			q := p.sections[i]
			if q.name != s.Name || q.virtualAddress != s.VirtualAddress || q.virtualSize != s.VirtualSize || q.rawOffset != s.Offset || q.rawSize != s.Size {
				t.Errorf("%s: section %d differs: %+v, reference %+v", name, i, q, s.SectionHeader)
			}
		}
		syms, err := ref.ImportedSymbols()
		if err != nil {
			t.Fatal(name, err)
		}
		var mine []string
		for _, imp := range p.imports {
			for _, f := range imp.functions {
				if f.ordinal < 0 {
					mine = append(mine, f.name+":"+imp.dll)
				}
			}
		}
		slices.Sort(mine)
		slices.Sort(syms)
		if !slices.Equal(mine, syms) {
			t.Errorf("%s: imports differ: %d, reference %d", name, len(mine), len(syms))
		}
		if p.calculatedChecksum() != opt.CheckSum && opt.CheckSum != 0 {
			t.Errorf("%s: checksum %x, stored %x", name, p.calculatedChecksum(), opt.CheckSum)
		}
		company := ""
		for _, kv := range p.version {
			if kv[0] == "CompanyName" {
				company = kv[1]
			}
		}
		if !strings.Contains(company, "Microsoft") || p.pdb == "" {
			t.Errorf("%s: version info %q, pdb %q", name, company, p.pdb)
		}
		t.Logf("%s: %d sections, %d DLLs imported, %d exports, %d resources, pdb %s", name, len(p.sections), len(p.imports), len(p.exports), len(p.resources), p.pdb)
	}
}

// Signed programs installed on this machine (Node.js, Python, Git and
// others, where present) verify in full against the system's roots,
// including their timestamps. Skipped in short mode, as it depends on what
// is installed.
func TestAuthenticodeInstalledPrograms(t *testing.T) {
	if os.Getenv("SystemRoot") == "" || testing.Short() {
		t.Skip("Windows, not in short mode")
	}
	found := 0
	for _, name := range []string{"node.exe", "python.exe", "git.exe", "pwsh.exe", "msedge.exe"} {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 200<<20 {
			continue
		}
		p := parsePE(data, false, 0)
		if p == nil {
			continue
		}
		sigs := p.signatures()
		if len(sigs) == 0 {
			continue
		}
		found++
		s := sigs[0]
		if !s.verified || s.digest != s.fileDigest || len(s.countersignatures) == 0 || !s.countersignatures[0].verified {
			t.Errorf("%s: verified %v, countersignatures %+v", path, s.verified, s.countersignatures)
		}
		t.Logf("%s: signed by %s", path, s.cert.subject)
	}
	if found == 0 {
		t.Skip("no signed programs found on the path")
	}
}
