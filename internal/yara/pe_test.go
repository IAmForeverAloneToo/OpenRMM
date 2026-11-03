package yara

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// A small 64-bit DLL built byte by byte: two sections, imports by name and
// by ordinal, exports with a forwarder, a version resource, a Rich header,
// a CodeView PDB path and an overlay. Its values are known exactly.
const (
	fxBase    = 0x140000000
	fxRdata   = 0x2000 // .rdata virtual address
	fxRdataAt = 0x600  // and file offset
	fxSize    = 0xC00  // file size before the overlay
)

type fixture []byte

func (f fixture) put16(off int, v uint16) { binary.LittleEndian.PutUint16(f[off:], v) }
func (f fixture) put32(off int, v uint32) { binary.LittleEndian.PutUint32(f[off:], v) }
func (f fixture) put64(off int, v uint64) { binary.LittleEndian.PutUint64(f[off:], v) }

// at is the file offset of an address in .rdata.
func at(rva int) int { return rva - fxRdata + fxRdataAt }

func wide(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// versionBlock is one VS_VERSIONINFO block: header, key, padding, value,
// padding and children.
func versionBlock(key string, value []byte, text bool, children ...[]byte) []byte {
	pad := func(b []byte) []byte {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	b := make([]byte, 6)
	b = append(b, wide(key)...)
	b = pad(append(b, 0, 0))
	valueLen := len(value)
	typ := uint16(0)
	if text {
		valueLen = len(value) / 2
		typ = 1
	}
	b = pad(append(b, value...))
	for _, c := range children {
		b = pad(append(b, c...))
	}
	binary.LittleEndian.PutUint16(b[0:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[2:], uint16(valueLen))
	binary.LittleEndian.PutUint16(b[4:], typ)
	return b
}

func buildFixture() []byte {
	f := make(fixture, fxSize+16)
	copy(f, "MZ")
	f.put32(0x3C, 0x100)
	// Rich header at 0x80: DanS, three zero words, two entries, Rich, key.
	key := uint32(0x5A5A1234)
	rich := []uint32{0x536E6144, 0, 0, 0, 0x0105<<16 | 30148, 3, 0x0104<<16 | 30148, 2}
	for i, w := range rich {
		f.put32(0x80+4*i, w^key)
	}
	f.put32(0xA0, 0x68636952)
	f.put32(0xA4, key)
	// PE signature, COFF header.
	copy(f[0x100:], "PE\x00\x00")
	f.put16(0x104, 0x8664)
	f.put16(0x106, 2)
	f.put32(0x108, 0x5F000000)
	f.put16(0x114, 0xF0)
	f.put16(0x116, 0x2022) // executable, large address aware, DLL
	// Optional header (PE32+) at 0x118.
	o := 0x118
	f.put16(o, 0x20B)
	f[o+2], f[o+3] = 14, 29
	f.put32(o+4, 0x200)
	f.put32(o+16, 0x1010)
	f.put32(o+20, 0x1000)
	f.put64(o+24, fxBase)
	f.put32(o+32, 0x1000)
	f.put32(o+36, 0x200)
	f.put16(o+40, 6)
	f.put16(o+48, 6)
	f.put32(o+56, 0x3000)
	f.put32(o+60, 0x400)
	f.put16(o+68, 3)
	f.put16(o+70, 0x8160)
	f.put32(o+108, 16)
	dir := func(i int, rva, size uint32) { f.put32(o+112+8*i, rva); f.put32(o+116+8*i, size) }
	dir(0, 0x2100, 0xB0)
	dir(1, 0x2000, 60)
	dir(2, 0x2300, 0x100)
	dir(6, 0x2200, 28)
	dir(12, 0x2060, 24)
	// Section table at 0x208.
	section := func(i int, name string, vsize, va, rawSize, raw, chars uint32) {
		s := 0x208 + 40*i
		copy(f[s:], name)
		f.put32(s+8, vsize)
		f.put32(s+12, va)
		f.put32(s+16, rawSize)
		f.put32(s+20, raw)
		f.put32(s+36, chars)
	}
	section(0, ".text", 0x100, 0x1000, 0x200, 0x400, 0x60000020)
	section(1, ".rdata", 0x600, fxRdata, 0x600, fxRdataAt, 0x40000040)
	// Imports: kernel32.dll by name, ws2_32.dll by ordinal 23.
	imp := func(i int, lookup, name, iat uint32) {
		d := at(0x2000 + 20*i)
		f.put32(d, lookup)
		f.put32(d+12, name)
		f.put32(d+16, iat)
	}
	imp(0, 0x2040, 0x20A0, 0x2060)
	imp(1, 0x2080, 0x20B0, 0x2090)
	for _, t := range []int{0x2040, 0x2060} {
		f.put64(at(t), 0x20C0)
		f.put64(at(t+8), 0x20D0)
	}
	f.put64(at(0x2080), 1<<63|23)
	f.put64(at(0x2090), 1<<63|23)
	copy(f[at(0x20A0):], "kernel32.dll\x00")
	copy(f[at(0x20B0):], "ws2_32.dll\x00")
	copy(f[at(0x20C2):], "CreateFileW\x00")
	copy(f[at(0x20D2):], "ExitProcess\x00")
	// Exports: Alpha (ordinal 1, in .text) and Beta (ordinal 2, forwarded).
	e := at(0x2100)
	f.put32(e+4, 0x60000000)
	f.put32(e+12, 0x2180)
	f.put32(e+16, 1)
	f.put32(e+20, 2)
	f.put32(e+24, 2)
	f.put32(e+28, 0x2128)
	f.put32(e+32, 0x2130)
	f.put32(e+36, 0x2138)
	f.put32(at(0x2128), 0x1010)
	f.put32(at(0x212C), 0x2190)
	f.put32(at(0x2130), 0x2170)
	f.put32(at(0x2134), 0x2178)
	f.put16(at(0x2138), 0)
	f.put16(at(0x213A), 1)
	copy(f[at(0x2170):], "Alpha\x00")
	copy(f[at(0x2178):], "Beta\x00")
	copy(f[at(0x2180):], "test.dll\x00")
	copy(f[at(0x2190):], "NTDLL.RtlZeroMemory\x00")
	// Debug: a CodeView entry with a PDB path.
	d := at(0x2200)
	f.put32(d+12, 2)
	f.put32(d+16, 48)
	f.put32(d+20, 0x2220)
	f.put32(d+24, uint32(at(0x2220)))
	copy(f[at(0x2220):], "RSDS")
	copy(f[at(0x2238):], "C:\\build\\test.pdb\x00")
	// Resources: type 16 (version), id 1, language 0x409.
	r := at(0x2300)
	f.put16(r+14, 1)
	f.put32(r+16, 16)
	f.put32(r+20, 1<<31|0x18)
	f.put16(r+0x18+14, 1)
	f.put32(r+0x28, 1)
	f.put32(r+0x2C, 1<<31|0x30)
	f.put16(r+0x30+14, 1)
	f.put32(r+0x40, 0x409)
	f.put32(r+0x44, 0x48)
	vi := versionBlock("VS_VERSION_INFO", make([]byte, 52), false,
		versionBlock("StringFileInfo", nil, true,
			versionBlock("040904B0", nil, true,
				versionBlock("CompanyName", append(wide("OpenRMM Test"), 0, 0), true),
				versionBlock("ProductName", append(wide("Fixture"), 0, 0), true))))
	f.put32(r+0x48, 0x2400)
	f.put32(r+0x4C, uint32(len(vi)))
	copy(f[at(0x2400):], vi)
	// Code at the entry point, and the overlay.
	copy(f[0x410:], "\x48\x31\xC0\xC3")
	copy(f[fxSize:], "overlay-overlay!")
	p := parsePE(f, false, 0)
	f.put32(o+64, p.calculatedChecksum())
	return f
}

// mapImage lays a file out as the loader would: headers, then each section
// at its virtual address.
func mapImage(file []byte) []byte {
	img := make([]byte, 0x3000)
	copy(img, file[:0x400])
	copy(img[0x1000:], file[0x400:0x600])
	copy(img[fxRdata:], file[fxRdataAt:fxRdataAt+0x600])
	return img
}

const fixtureRules = `import "pe" import "hash"
rule headers { condition: pe.is_pe and pe.machine == pe.MACHINE_AMD64 and pe.number_of_sections == 2 and pe.timestamp == 0x5F000000
  and pe.is_dll() and pe.is_64bit() and not pe.is_32bit() and pe.characteristics & pe.DLL and pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI
  and pe.linker_version.major == 14 and pe.linker_version.minor == 29 and pe.image_base == 0x140000000 and pe.opthdr_magic == pe.IMAGE_NT_OPTIONAL_HDR64_MAGIC
  and pe.dll_characteristics & pe.NX_COMPAT and pe.size_of_image == 0x3000 and pe.number_of_rva_and_sizes == 16 and pe.entry_point_raw == 0x1010
  and pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address == 0x2000 }
rule sections { condition: pe.sections[0].name == ".text" and pe.sections[1].virtual_address == 0x2000 and pe.section_index(".rdata") == 1
  and for any s in pe.sections : ( s.name == ".rdata" and s.characteristics & pe.SECTION_CNT_INITIALIZED_DATA ) }
rule imports { condition: pe.imports("KERNEL32.dll", "CreateFileW") and pe.imports("ws2_32.dll", 23) and pe.imports("kernel32.dll") == 2
  and pe.imports(/kernel/i, /File/) == 1 and pe.imports(pe.IMPORT_ANY, "kernel32.dll", "ExitProcess") and not pe.imports(pe.IMPORT_DELAYED, "kernel32.dll", "ExitProcess")
  and not pe.imports("kernel32.dll", "createfilew") and pe.number_of_imports == 2 and pe.number_of_imported_functions == 3
  and pe.import_details[1].functions[0].ordinal == 23 and pe.import_details[0].library_name == "kernel32.dll"
  and pe.imphash() == hash.md5("kernel32.createfilew,kernel32.exitprocess,ws2_32.socket") }
rule exports { condition: pe.exports("Alpha") and pe.exports(2) and pe.exports(/^Be/) and not pe.exports("Gamma") and pe.exports_index("Beta") == 1
  and pe.number_of_exports == 2 and pe.dll_name == "test.dll" and pe.export_timestamp == 0x60000000
  and pe.export_details[1].forward_name == "NTDLL.RtlZeroMemory" and not defined pe.export_details[1].offset }
rule resources { condition: pe.number_of_resources == 1 and pe.resources[0].type == pe.RESOURCE_TYPE_VERSION and pe.resources[0].language == 0x409
  and pe.language(9) and pe.locale(0x409) and not pe.language(7)
  and pe.version_info["CompanyName"] == "OpenRMM Test" and pe.version_info_list[1].value == "Fixture" }
rule rich { condition: pe.rich_signature.key == 0x5A5A1234 and pe.rich_signature.version(30148) == 5 and pe.rich_signature.toolid(0x105) == 3
  and pe.rich_signature.toolid(0x104, 30148) == 2 and pe.rich_signature.clear_data startswith "DanS" }
rule debug { condition: pe.pdb_path == "C:\\build\\test.pdb" }
`

func TestPEFile(t *testing.T) {
	file := buildFixture()
	rules := fixtureRules + `
rule file_only { condition: pe.entry_point == 0x410 and entrypoint == 0x410 and uint32(pe.entry_point) == 0xC3C03148
  and pe.overlay.offset == 0xC00 and pe.overlay.size == 16 and pe.checksum == pe.calculate_checksum() and pe.checksum != 0
  and pe.export_details[0].offset == 0x410 and pe.rva_to_offset(0x2100) == 0x700 and pe.section_index(0x610) == 1
  and pe.rich_signature.offset == 0x80 and pe.rich_signature.length == 32 }`
	if got := scanText(t, rules, string(file)); strings.Join(got, ",") != "headers,sections,imports,exports,resources,rich,debug,file_only" {
		t.Fatal(got)
	}
}

// The same DLL mapped in a process: addresses are virtual addresses.
func TestPEImage(t *testing.T) {
	img := mapImage(buildFixture())
	rules := fixtureRules + `
rule image_only { condition: pe.entry_point == 0x140001010 and entrypoint == 0x140001010 and uint32(pe.entry_point) == 0xC3C03148
  and not defined pe.overlay.offset and not defined pe.calculate_checksum() and pe.export_details[0].offset == 0x140001010
  and pe.section_index(0x140002010) == 1 }`
	rs, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	blocks := []Block{{Base: 0x10000, Data: []byte("unrelated")}, {Base: fxBase, Data: img}}
	m, err := rs.ScanTarget(context.Background(), blocks, -1, Target{Image: &Block{Base: fxBase, Data: img}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range m {
		names = append(names, x.Rule)
	}
	if strings.Join(names, ",") != "headers,sections,imports,exports,resources,rich,debug,image_only" {
		t.Fatal(names)
	}
}

// Data that is not a PE leaves the module undefined but its constants set.
func TestPENotPE(t *testing.T) {
	got := scanText(t, `import "pe"
rule not_pe { condition: not pe.is_pe and not defined pe.number_of_sections and pe.MACHINE_I386 == 0x14c and not defined pe.imports("a.dll", "b") }
rule no_entry { condition: not defined entrypoint }`, "MZ but not a PE file at all")
	if strings.Join(got, ",") != "not_pe,no_entry" {
		t.Fatal(got)
	}
}

// Damaged and truncated copies of the DLL never panic; a parse stays cheap.
func TestPEDamaged(t *testing.T) {
	file := buildFixture()
	for n := range len(file) {
		parsePE(file[:n], false, 0)
	}
	seed := uint32(7)
	for range 20000 {
		c := append([]byte(nil), file...)
		for range 1 + seed%8 {
			seed = seed*1664525 + 1013904223
			c[int(seed>>8)%len(c)] = byte(seed >> 24)
		}
		if p := parsePE(c, false, 0); p != nil {
			p.imphashInput()
			p.calculatedChecksum()
		}
		parsePE(c, true, fxBase)
	}
}

func FuzzParsePE(f *testing.F) {
	f.Add(buildFixture())
	f.Add(mapImage(buildFixture()))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, image := range []bool{false, true} {
			if p := parsePE(data, image, fxBase); p != nil {
				p.imphashInput()
				if !image {
					p.calculatedChecksum()
					p.overlay()
				}
			}
		}
	})
}
