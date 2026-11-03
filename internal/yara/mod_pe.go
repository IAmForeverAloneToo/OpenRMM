package yara

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// The pe module: the headers, sections, imports, exports, resources,
// version information, Rich header and debug information of a PE file, or
// of a process's main executable image in a memory scan. Field names and
// meanings follow YARA's pe module; offsets in a memory scan are virtual
// addresses.

const (
	importStandard = 1
	importDelayed  = 2
	importAny      = 3
)

var peConstants = map[string]int64{
	"MACHINE_UNKNOWN": 0x0, "MACHINE_AM33": 0x1D3, "MACHINE_AMD64": 0x8664, "MACHINE_ARM": 0x1C0, "MACHINE_ARMNT": 0x1C4,
	"MACHINE_ARM64": 0xAA64, "MACHINE_EBC": 0xEBC, "MACHINE_I386": 0x14C, "MACHINE_IA64": 0x200, "MACHINE_M32R": 0x9041,
	"MACHINE_MIPS16": 0x266, "MACHINE_MIPSFPU": 0x366, "MACHINE_MIPSFPU16": 0x466, "MACHINE_POWERPC": 0x1F0,
	"MACHINE_POWERPCFP": 0x1F1, "MACHINE_R4000": 0x166, "MACHINE_SH3": 0x1A2, "MACHINE_SH3DSP": 0x1A3, "MACHINE_SH4": 0x1A6,
	"MACHINE_SH5": 0x1A8, "MACHINE_THUMB": 0x1C2, "MACHINE_WCEMIPSV2": 0x169, "MACHINE_TARGET_HOST": 0x1, "MACHINE_R3000": 0x162,
	"MACHINE_R10000": 0x168, "MACHINE_ALPHA": 0x184, "MACHINE_SH3E": 0x1A4, "MACHINE_ALPHA64": 0x284, "MACHINE_AXP64": 0x284,
	"MACHINE_TRICORE": 0x520, "MACHINE_CEF": 0xCEF, "MACHINE_CEE": 0xC0EE, "MACHINE_RISCV32": 0x5032, "MACHINE_RISCV64": 0x5064,
	"MACHINE_RISCV128": 0x5128, "MACHINE_LOONGARCH32": 0x6232, "MACHINE_LOONGARCH64": 0x6264,

	"SUBSYSTEM_UNKNOWN": 0, "SUBSYSTEM_NATIVE": 1, "SUBSYSTEM_WINDOWS_GUI": 2, "SUBSYSTEM_WINDOWS_CUI": 3, "SUBSYSTEM_OS2_CUI": 5,
	"SUBSYSTEM_POSIX_CUI": 7, "SUBSYSTEM_NATIVE_WINDOWS": 8, "SUBSYSTEM_WINDOWS_CE_GUI": 9, "SUBSYSTEM_EFI_APPLICATION": 10,
	"SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": 11, "SUBSYSTEM_EFI_RUNTIME_DRIVER": 12, "SUBSYSTEM_EFI_ROM_IMAGE": 13, "SUBSYSTEM_XBOX": 14,
	"SUBSYSTEM_WINDOWS_BOOT_APPLICATION": 16,

	"RELOCS_STRIPPED": 0x1, "EXECUTABLE_IMAGE": 0x2, "LINE_NUMS_STRIPPED": 0x4, "LOCAL_SYMS_STRIPPED": 0x8, "AGGRESIVE_WS_TRIM": 0x10,
	"LARGE_ADDRESS_AWARE": 0x20, "BYTES_REVERSED_LO": 0x80, "MACHINE_32BIT": 0x100, "DEBUG_STRIPPED": 0x200,
	"REMOVABLE_RUN_FROM_SWAP": 0x400, "NET_RUN_FROM_SWAP": 0x800, "SYSTEM": 0x1000, "DLL": 0x2000, "UP_SYSTEM_ONLY": 0x4000,
	"BYTES_REVERSED_HI": 0x8000,

	"HIGH_ENTROPY_VA": 0x20, "DYNAMIC_BASE": 0x40, "FORCE_INTEGRITY": 0x80, "NX_COMPAT": 0x100, "NO_ISOLATION": 0x200,
	"NO_SEH": 0x400, "NO_BIND": 0x800, "APPCONTAINER": 0x1000, "WDM_DRIVER": 0x2000, "GUARD_CF": 0x4000, "TERMINAL_SERVER_AWARE": 0x8000,

	"SECTION_NO_PAD": 0x8, "SECTION_CNT_CODE": 0x20, "SECTION_CNT_INITIALIZED_DATA": 0x40, "SECTION_CNT_UNINITIALIZED_DATA": 0x80,
	"SECTION_LNK_OTHER": 0x100, "SECTION_LNK_INFO": 0x200, "SECTION_LNK_REMOVE": 0x800, "SECTION_LNK_COMDAT": 0x1000,
	"SECTION_NO_DEFER_SPEC_EXC": 0x4000, "SECTION_GPREL": 0x8000, "SECTION_MEM_PURGEABLE": 0x20000, "SECTION_MEM_16BIT": 0x20000,
	"SECTION_MEM_LOCKED": 0x40000, "SECTION_MEM_PRELOAD": 0x80000, "SECTION_ALIGN_1BYTES": 0x100000, "SECTION_ALIGN_2BYTES": 0x200000,
	"SECTION_ALIGN_4BYTES": 0x300000, "SECTION_ALIGN_8BYTES": 0x400000, "SECTION_ALIGN_16BYTES": 0x500000,
	"SECTION_ALIGN_32BYTES": 0x600000, "SECTION_ALIGN_64BYTES": 0x700000, "SECTION_ALIGN_128BYTES": 0x800000,
	"SECTION_ALIGN_256BYTES": 0x900000, "SECTION_ALIGN_512BYTES": 0xA00000, "SECTION_ALIGN_1024BYTES": 0xB00000,
	"SECTION_ALIGN_2048BYTES": 0xC00000, "SECTION_ALIGN_4096BYTES": 0xD00000, "SECTION_ALIGN_8192BYTES": 0xE00000,
	"SECTION_ALIGN_MASK": 0xF00000, "SECTION_LNK_NRELOC_OVFL": 0x1000000, "SECTION_MEM_DISCARDABLE": 0x2000000,
	"SECTION_MEM_NOT_CACHED": 0x4000000, "SECTION_MEM_NOT_PAGED": 0x8000000, "SECTION_MEM_SHARED": 0x10000000,
	"SECTION_MEM_EXECUTE": 0x20000000, "SECTION_MEM_READ": 0x40000000, "SECTION_MEM_WRITE": 0x80000000,
	"SECTION_SCALE_INDEX": 0x1,

	"IMAGE_DIRECTORY_ENTRY_EXPORT": 0, "IMAGE_DIRECTORY_ENTRY_IMPORT": 1, "IMAGE_DIRECTORY_ENTRY_RESOURCE": 2,
	"IMAGE_DIRECTORY_ENTRY_EXCEPTION": 3, "IMAGE_DIRECTORY_ENTRY_SECURITY": 4, "IMAGE_DIRECTORY_ENTRY_BASERELOC": 5,
	"IMAGE_DIRECTORY_ENTRY_DEBUG": 6, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE": 7, "IMAGE_DIRECTORY_ENTRY_COPYRIGHT": 7,
	"IMAGE_DIRECTORY_ENTRY_GLOBALPTR": 8, "IMAGE_DIRECTORY_ENTRY_TLS": 9, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": 10,
	"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": 11, "IMAGE_DIRECTORY_ENTRY_IAT": 12, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": 13,
	"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR": 14,
	"IMAGE_NT_OPTIONAL_HDR32_MAGIC":        0x10B, "IMAGE_NT_OPTIONAL_HDR64_MAGIC": 0x20B, "IMAGE_ROM_OPTIONAL_HDR_MAGIC": 0x107,

	"RESOURCE_TYPE_CURSOR": 1, "RESOURCE_TYPE_BITMAP": 2, "RESOURCE_TYPE_ICON": 3, "RESOURCE_TYPE_MENU": 4, "RESOURCE_TYPE_DIALOG": 5,
	"RESOURCE_TYPE_STRING": 6, "RESOURCE_TYPE_FONTDIR": 7, "RESOURCE_TYPE_FONT": 8, "RESOURCE_TYPE_ACCELERATOR": 9,
	"RESOURCE_TYPE_RCDATA": 10, "RESOURCE_TYPE_MESSAGETABLE": 11, "RESOURCE_TYPE_GROUP_CURSOR": 12, "RESOURCE_TYPE_GROUP_ICON": 14,
	"RESOURCE_TYPE_VERSION": 16, "RESOURCE_TYPE_DLGINCLUDE": 17, "RESOURCE_TYPE_PLUGPLAY": 19, "RESOURCE_TYPE_VXD": 20,
	"RESOURCE_TYPE_ANICURSOR": 21, "RESOURCE_TYPE_ANIICON": 22, "RESOURCE_TYPE_HTML": 23, "RESOURCE_TYPE_MANIFEST": 24,

	"IMPORT_STANDARD": importStandard, "IMPORT_DELAYED": importDelayed, "IMPORT_ANY": importAny,
}

// peModule is the registered pe module (the entrypoint keyword reads it).
var peModule *module

func init() {
	pair := func(a, b string) *ftype { return structT(map[string]*ftype{a: tInt, b: tInt}) }
	function := structT(map[string]*ftype{"name": tStr, "ordinal": tInt, "rva": tInt})
	importDetail := structT(map[string]*ftype{"library_name": tStr, "number_of_functions": tInt, "functions": arrayT(function)})
	fields := map[string]*ftype{
		"is_pe": tInt, "machine": tInt, "number_of_sections": tInt, "timestamp": tInt, "pointer_to_symbol_table": tInt,
		"number_of_symbols": tInt, "size_of_optional_header": tInt, "characteristics": tInt,
		"entry_point": tInt, "entry_point_raw": tInt, "image_base": tInt, "number_of_rva_and_sizes": tInt,
		"opthdr_magic": tInt, "size_of_code": tInt, "size_of_initialized_data": tInt, "size_of_uninitialized_data": tInt,
		"base_of_code": tInt, "base_of_data": tInt, "section_alignment": tInt, "file_alignment": tInt,
		"win32_version_value": tInt, "size_of_image": tInt, "size_of_headers": tInt, "checksum": tInt, "subsystem": tInt,
		"dll_characteristics": tInt, "size_of_stack_reserve": tInt, "size_of_stack_commit": tInt,
		"size_of_heap_reserve": tInt, "size_of_heap_commit": tInt, "loader_flags": tInt,
		"linker_version": pair("major", "minor"), "os_version": pair("major", "minor"),
		"image_version": pair("major", "minor"), "subsystem_version": pair("major", "minor"),
		"data_directories": arrayT(pair("virtual_address", "size")),
		"sections": arrayT(structT(map[string]*ftype{
			"name": tStr, "full_name": tStr, "characteristics": tInt, "virtual_address": tInt, "virtual_size": tInt,
			"raw_data_offset": tInt, "raw_data_size": tInt, "pointer_to_relocations": tInt, "pointer_to_line_numbers": tInt,
			"number_of_relocations": tInt, "number_of_line_numbers": tInt,
		})),
		"overlay":           pair("offset", "size"),
		"number_of_imports": tInt, "number_of_imported_functions": tInt,
		"number_of_delayed_imports": tInt, "number_of_delayed_imported_functions": tInt,
		"import_details": arrayT(importDetail), "delayed_import_details": arrayT(importDetail),
		"number_of_exports": tInt, "export_timestamp": tInt, "dll_name": tStr,
		"export_details":      arrayT(structT(map[string]*ftype{"offset": tInt, "name": tStr, "forward_name": tStr, "ordinal": tInt, "rva": tInt})),
		"number_of_resources": tInt, "resource_timestamp": tInt, "resource_version": pair("major", "minor"),
		"resources": arrayT(structT(map[string]*ftype{
			"rva": tInt, "offset": tInt, "length": tInt, "type": tInt, "id": tInt, "language": tInt,
			"type_string": tStr, "name_string": tStr, "language_string": tStr,
		})),
		"version_info":      dictT(tStr),
		"version_info_list": arrayT(structT(map[string]*ftype{"key": tStr, "value": tStr})),
		"pdb_path":          tStr,
		"rich_signature": structT(map[string]*ftype{
			"offset": tInt, "length": tInt, "key": tInt, "raw_data": tStr, "clear_data": tStr, "version_data": tStr,
			"version": funcT(
				overload("i", tInt, func(_ *evaluator, self any, a []value) value { return richCount(self, a[0].i, -1, true) }),
				overload("ii", tInt, func(_ *evaluator, self any, a []value) value { return richCount(self, a[0].i, a[1].i, true) }),
			),
			"toolid": funcT(
				overload("i", tInt, func(_ *evaluator, self any, a []value) value { return richCount(self, a[0].i, -1, false) }),
				overload("ii", tInt, func(_ *evaluator, self any, a []value) value { return richCount(self, a[0].i, a[1].i, false) }),
			),
		}),
		"imports":       funcT(importOverloads()...),
		"exports":       funcT(exportOverloads(false)...),
		"exports_index": funcT(exportOverloads(true)...),
		"imphash":       funcT(overload("", tStr, withPE(func(p *peFile, _ []value) value { return value{kind: 's', s: md5Hex(p.imphashInput())} }))),
		"is_dll":        funcT(overload("", tBool, withPE(func(p *peFile, _ []value) value { return boolV(p.characteristics&0x2000 != 0) }))),
		"is_32bit":      funcT(overload("", tBool, withPE(func(p *peFile, _ []value) value { return boolV(p.magic == 0x10B) }))),
		"is_64bit":      funcT(overload("", tBool, withPE(func(p *peFile, _ []value) value { return boolV(p.magic == 0x20B) }))),
		"calculate_checksum": funcT(overload("", tInt, withPE(func(p *peFile, _ []value) value {
			if p.image {
				return undefined
			}
			return intV(int64(p.calculatedChecksum()))
		}))),
		"rva_to_offset": funcT(overload("i", tInt, withPE(func(p *peFile, a []value) value {
			if a[0].i < 0 || a[0].i > 0xFFFFFFFF {
				return undefined
			}
			off, ok := p.offset(uint32(a[0].i))
			if !ok {
				return undefined
			}
			return intV(p.address(off))
		}))),
		"section_index": funcT(
			overload("s", tInt, withPE(func(p *peFile, a []value) value {
				for i, s := range p.sections {
					if s.name == a[0].s {
						return intV(int64(i))
					}
				}
				return undefined
			})),
			overload("i", tInt, withPE(func(p *peFile, a []value) value {
				for i, s := range p.sections {
					lo, size := int64(s.rawOffset), int64(s.rawSize)
					if p.image {
						lo, size = int64(p.base)+int64(s.virtualAddress), int64(s.virtualSize)
					}
					if a[0].i >= lo && a[0].i < lo+size {
						return intV(int64(i))
					}
				}
				return undefined
			})),
		),
		"language": funcT(overload("i", tBool, withPE(func(p *peFile, a []value) value {
			for _, r := range p.resources {
				if r.language >= 0 && r.language&0xFF == a[0].i {
					return boolV(true)
				}
			}
			return boolV(false)
		}))),
		"locale": funcT(overload("i", tBool, withPE(func(p *peFile, a []value) value {
			for _, r := range p.resources {
				if r.language >= 0 && r.language == a[0].i {
					return boolV(true)
				}
			}
			return boolV(false)
		}))),
	}
	for name := range peConstants {
		fields[name] = tInt
	}
	peModule = &module{name: "pe", t: structT(fields), load: loadPE}
	register(peModule)
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// peKey is where the parsed file is kept in the module data.
const peKey = "\x00pe"

// withPE runs a function on the parsed PE, undefined when it is none.
func withPE(f func(p *peFile, a []value) value) func(*evaluator, any, []value) value {
	return func(_ *evaluator, self any, a []value) value {
		s, _ := self.(obj)
		p, ok := s[peKey].(*peFile)
		if !ok {
			return undefined
		}
		return f(p, a)
	}
}

// address is where data at off of the parsed bytes is in the scan: the
// file offset, or the virtual address in a mapped image.
func (p *peFile) address(off uint64) int64 {
	if p.image {
		return int64(p.base + off)
	}
	return int64(off)
}

// loadPE parses the scanned file, or the process image of a memory scan.
func loadPE(e *evaluator) any {
	root := obj{}
	for name, v := range peConstants {
		root[name] = v
	}
	var p *peFile
	switch {
	case e.target.Image != nil:
		p = parsePE(e.target.Image.Data, true, e.target.Image.Base)
	case e.size >= 0 && len(e.blocks) == 1 && e.blocks[0].Base == 0:
		p = parsePE(e.blocks[0].Data, false, 0)
	}
	if p == nil {
		root["is_pe"] = int64(0)
		return root
	}
	root[peKey] = p
	root["is_pe"] = int64(1)
	set := func(name string, v any) { root[name] = v }
	set("machine", int64(p.machine))
	set("number_of_sections", int64(p.numSections))
	set("timestamp", int64(p.timestamp))
	set("pointer_to_symbol_table", int64(p.symbolTable))
	set("number_of_symbols", int64(p.numSymbols))
	set("size_of_optional_header", int64(p.optSize))
	set("characteristics", int64(p.characteristics))
	set("entry_point_raw", int64(p.entry))
	if p.image {
		set("entry_point", int64(p.base)+int64(p.entry))
	} else if off, ok := p.offset(p.entry); ok {
		set("entry_point", int64(off))
	}
	set("image_base", int64(p.imageBase))
	set("number_of_rva_and_sizes", int64(p.numRvaSizes))
	set("opthdr_magic", int64(p.magic))
	set("size_of_code", int64(p.sizeCode))
	set("size_of_initialized_data", int64(p.sizeInit))
	set("size_of_uninitialized_data", int64(p.sizeUninit))
	set("base_of_code", int64(p.baseOfCode))
	if !p.is64 {
		set("base_of_data", int64(p.baseOfData))
	}
	set("section_alignment", int64(p.sectionAlign))
	set("file_alignment", int64(p.fileAlign))
	set("win32_version_value", int64(p.win32Version))
	set("size_of_image", int64(p.sizeImage))
	set("size_of_headers", int64(p.sizeHeaders))
	set("checksum", int64(p.checksum))
	set("subsystem", int64(p.subsystem))
	set("dll_characteristics", int64(p.dllCharacteristics))
	set("size_of_stack_reserve", int64(p.stackReserve))
	set("size_of_stack_commit", int64(p.stackCommit))
	set("size_of_heap_reserve", int64(p.heapReserve))
	set("size_of_heap_commit", int64(p.heapCommit))
	set("loader_flags", int64(p.loaderFlags))
	version := func(v [2]uint16) obj { return obj{"major": int64(v[0]), "minor": int64(v[1])} }
	set("linker_version", obj{"major": int64(p.linker[0]), "minor": int64(p.linker[1])})
	set("os_version", version(p.osVersion))
	set("image_version", version(p.imageVersion))
	set("subsystem_version", version(p.subsystemVersion))
	dirs := arr{}
	for _, d := range p.dirs {
		dirs = append(dirs, obj{"virtual_address": int64(d[0]), "size": int64(d[1])})
	}
	set("data_directories", dirs)
	sections := arr{}
	for _, s := range p.sections {
		sections = append(sections, obj{
			"name": s.name, "full_name": s.fullName, "characteristics": int64(s.characteristics),
			"virtual_address": int64(s.virtualAddress), "virtual_size": int64(s.virtualSize),
			"raw_data_offset": int64(s.rawOffset), "raw_data_size": int64(s.rawSize),
			"pointer_to_relocations": int64(s.relocations), "pointer_to_line_numbers": int64(s.lineNumbers),
			"number_of_relocations": int64(s.numRelocations), "number_of_line_numbers": int64(s.numLineNumbers),
		})
	}
	set("sections", sections)
	if !p.image {
		off, size := p.overlay()
		set("overlay", obj{"offset": int64(off), "size": int64(size)})
	}
	details := func(list []peImport) (arr, int64) {
		out, n := arr{}, int64(0)
		for _, imp := range list {
			fs := arr{}
			for _, f := range imp.functions {
				o := obj{"rva": int64(f.rva)}
				if f.ordinal >= 0 {
					o["ordinal"] = f.ordinal
				} else {
					o["name"] = f.name
				}
				fs = append(fs, o)
			}
			n += int64(len(fs))
			out = append(out, obj{"library_name": imp.dll, "number_of_functions": int64(len(fs)), "functions": fs})
		}
		return out, n
	}
	d, n := details(p.imports)
	set("import_details", d)
	set("number_of_imports", int64(len(p.imports)))
	set("number_of_imported_functions", n)
	d, n = details(p.delayed)
	set("delayed_import_details", d)
	set("number_of_delayed_imports", int64(len(p.delayed)))
	set("number_of_delayed_imported_functions", n)
	if p.hasExports {
		ex := arr{}
		for _, x := range p.exports {
			o := obj{"ordinal": x.ordinal, "rva": int64(x.rva)}
			if x.name != "" {
				o["name"] = x.name
			}
			if x.forward != "" {
				o["forward_name"] = x.forward
			} else if off, ok := p.offset(x.rva); ok {
				o["offset"] = p.address(off)
			}
			ex = append(ex, o)
		}
		set("export_details", ex)
		set("number_of_exports", int64(len(p.exports)))
		set("export_timestamp", int64(p.exportTimestamp))
		set("dll_name", p.dllName)
	} else {
		set("number_of_exports", int64(0))
	}
	if p.hasResources {
		rs := arr{}
		for _, r := range p.resources {
			o := obj{"rva": int64(r.rva), "length": int64(r.length)}
			if off, ok := p.offset(r.rva); ok {
				o["offset"] = p.address(off)
			}
			for _, f := range []struct {
				key, nameKey string
				id           int64
				name         string
			}{{"type", "type_string", r.typ, r.typeName}, {"id", "name_string", r.id, r.idName}, {"language", "language_string", r.language, r.languageName}} {
				if f.id >= 0 {
					o[f.key] = f.id
				} else {
					o[f.nameKey] = f.name
				}
			}
			rs = append(rs, o)
		}
		set("resources", rs)
		set("number_of_resources", int64(len(p.resources)))
		set("resource_timestamp", int64(p.resourceTimestamp))
		set("resource_version", version(p.resourceVersion))
	} else {
		set("number_of_resources", int64(0))
	}
	vi, list := dict{}, arr{}
	for _, kv := range p.version {
		vi[kv[0]] = kv[1]
		list = append(list, obj{"key": kv[0], "value": kv[1]})
	}
	set("version_info", vi)
	set("version_info_list", list)
	if p.pdb != "" {
		set("pdb_path", p.pdb)
	}
	if r := p.rich; r != nil {
		var vd strings.Builder
		for _, e := range r.entries {
			vd.WriteString(string([]byte{byte(e[0]), byte(e[0] >> 8), byte(e[0] >> 16), byte(e[0] >> 24)}))
		}
		set("rich_signature", obj{
			"offset": p.address(uint64(r.offset)), "length": int64(r.length), "key": int64(r.key),
			"raw_data": string(r.raw), "clear_data": string(r.clear), "version_data": vd.String(), peKey: r,
		})
	}
	return root
}

// richCount sums the counts of Rich header entries with a build number
// (version) or product id (toolid), optionally with the other as well.
func richCount(self any, first, second int64, byVersion bool) value {
	s, _ := self.(obj)
	r, ok := s[peKey].(*peRich)
	if !ok {
		return undefined
	}
	var n int64
	for _, e := range r.entries {
		build, product := int64(e[0]&0xFFFF), int64(e[0]>>16)
		a, b := build, product
		if !byVersion {
			a, b = product, build
		}
		if a == first && (second < 0 || b == second) {
			n += int64(e[1])
		}
	}
	return intV(n)
}

// importOverloads are pe.imports(...): with a flag (standard, delayed or
// any) or without (standard), by DLL and function name or ordinal, by DLL
// (the number of its functions), or by regular expressions (the number of
// matching functions). DLL names compare without case.
func importOverloads() []*fn {
	lists := func(p *peFile, flags int64) [][]peImport {
		var out [][]peImport
		if flags&importStandard != 0 {
			out = append(out, p.imports)
		}
		if flags&importDelayed != 0 {
			out = append(out, p.delayed)
		}
		return out
	}
	count := func(p *peFile, flags int64, dll func(string) bool, f func(peFunction) bool) int64 {
		var n int64
		for _, list := range lists(p, flags) {
			for _, imp := range list {
				if !dll(imp.dll) {
					continue
				}
				for _, fn := range imp.functions {
					if f(fn) {
						n++
					}
				}
			}
		}
		return n
	}
	byName := func(dll, name string) (func(string) bool, func(peFunction) bool) {
		return func(d string) bool { return strings.EqualFold(d, dll) }, func(f peFunction) bool { return f.ordinal < 0 && f.name == name }
	}
	byOrdinal := func(dll string, ord int64) (func(string) bool, func(peFunction) bool) {
		return func(d string) bool { return strings.EqualFold(d, dll) }, func(f peFunction) bool { return f.ordinal == ord }
	}
	every := func(peFunction) bool { return true }
	return []*fn{
		overload("ss", tBool, withPE(func(p *peFile, a []value) value {
			d, f := byName(a[0].s, a[1].s)
			return boolV(count(p, importStandard, d, f) > 0)
		})),
		overload("si", tBool, withPE(func(p *peFile, a []value) value {
			d, f := byOrdinal(a[0].s, a[1].i)
			return boolV(count(p, importStandard, d, f) > 0)
		})),
		overload("s", tInt, withPE(func(p *peFile, a []value) value {
			return intV(count(p, importStandard, func(d string) bool { return strings.EqualFold(d, a[0].s) }, every))
		})),
		overload("rr", tInt, withPE(func(p *peFile, a []value) value {
			return intV(count(p, importStandard, func(d string) bool { return regexMatch(a[0], d) }, func(f peFunction) bool { return f.name != "" && regexMatch(a[1], f.name) }))
		})),
		overload("iss", tBool, withPE(func(p *peFile, a []value) value {
			d, f := byName(a[1].s, a[2].s)
			return boolV(count(p, a[0].i, d, f) > 0)
		})),
		overload("isi", tBool, withPE(func(p *peFile, a []value) value {
			d, f := byOrdinal(a[1].s, a[2].i)
			return boolV(count(p, a[0].i, d, f) > 0)
		})),
		overload("is", tInt, withPE(func(p *peFile, a []value) value {
			return intV(count(p, a[0].i, func(d string) bool { return strings.EqualFold(d, a[1].s) }, every))
		})),
		overload("irr", tInt, withPE(func(p *peFile, a []value) value {
			return intV(count(p, a[0].i, func(d string) bool { return regexMatch(a[1], d) }, func(f peFunction) bool { return f.name != "" && regexMatch(a[2], f.name) }))
		})),
	}
}

// exportOverloads are pe.exports(name|ordinal|regex), true when exported,
// or with index pe.exports_index(...), the position in export_details.
func exportOverloads(index bool) []*fn {
	find := func(p *peFile, match func(peExport) bool) value {
		for i, x := range p.exports {
			if match(x) {
				if index {
					return intV(int64(i))
				}
				return boolV(true)
			}
		}
		if index {
			return undefined
		}
		return boolV(false)
	}
	ret := tBool
	if index {
		ret = tInt
	}
	return []*fn{
		overload("s", ret, withPE(func(p *peFile, a []value) value {
			return find(p, func(x peExport) bool { return x.name == a[0].s })
		})),
		overload("i", ret, withPE(func(p *peFile, a []value) value {
			return find(p, func(x peExport) bool { return x.ordinal == a[0].i })
		})),
		overload("r", ret, withPE(func(p *peFile, a []value) value {
			return find(p, func(x peExport) bool { return x.name != "" && regexMatch(a[0], x.name) })
		})),
	}
}
