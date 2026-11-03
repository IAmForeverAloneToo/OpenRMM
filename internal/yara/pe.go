package yara

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A strict parser of Windows PE files for the pe module. Files are hostile
// input: every read is bounds-checked, every table has a limit, and resource
// directories are visited once. It parses a file (data at file offsets) or a
// process's mapped image (data at relative virtual addresses).

// Limits on what is parsed of one PE.
const (
	peMaxSections    = 96 // as the Windows loader
	peMaxDLLs        = 4096
	peMaxFunctions   = 65536 // imported functions, all DLLs together
	peMaxExports     = 65536
	peMaxResources   = 65536
	peMaxVersion     = 1024 // version info strings
	peMaxName        = 1024 // bytes of one name
	peMaxDebug       = 64
	peMaxRichEntries = 1024
)

type peSection struct {
	name, fullName                                  string
	virtualSize, virtualAddress, rawSize, rawOffset uint32
	relocations, lineNumbers                        uint32
	numRelocations, numLineNumbers                  uint16
	characteristics                                 uint32
}

type peFunction struct {
	name    string // empty for an import by ordinal
	ordinal int64  // -1 when imported by name
	rva     uint32 // the address table entry
}

type peImport struct {
	dll       string
	functions []peFunction
}

type peExport struct {
	name, forward string
	ordinal       int64
	rva           uint32
}

type peResource struct {
	rva, length                    uint32
	typ, id, language              int64 // -1 when named
	typeName, idName, languageName string
}

type peRich struct {
	offset, length int
	key            uint32
	raw, clear     []byte
	entries        [][2]uint32 // comp id, count
}

type peFile struct {
	data  []byte
	image bool   // data is a mapped image: addresses are offsets
	base  uint64 // the image's address in memory

	lfanew                                         uint32
	machine, numSections, optSize, characteristics uint16
	timestamp, symbolTable, numSymbols             uint32

	magic                                              uint16
	is64                                               bool
	linker                                             [2]uint8
	sizeCode, sizeInit, sizeUninit                     uint32
	entry, baseOfCode, baseOfData                      uint32
	imageBase                                          uint64
	sectionAlign, fileAlign                            uint32
	osVersion, imageVersion, subsystemVersion          [2]uint16
	win32Version, sizeImage, sizeHeaders, checksum     uint32
	subsystem, dllCharacteristics                      uint16
	stackReserve, stackCommit, heapReserve, heapCommit uint64
	loaderFlags, numRvaSizes                           uint32
	dirs                                               [][2]uint32 // virtual address, size

	sections          []peSection
	imports           []peImport
	delayed           []peImport
	exports           []peExport
	exportTimestamp   uint32
	dllName           string
	hasExports        bool
	resources         []peResource
	resourceTimestamp uint32
	resourceVersion   [2]uint16
	hasResources      bool
	version           [][2]string
	rich              *peRich
	pdb               string
	// optOffset is where the optional header starts.
	optOffset uint32
}

func (p *peFile) bytesAt(off, n uint64) ([]byte, bool) {
	if off > uint64(len(p.data)) || n > uint64(len(p.data))-off {
		return nil, false
	}
	return p.data[off : off+n], true
}

func (p *peFile) u16(off uint64) (uint16, bool) {
	b, ok := p.bytesAt(off, 2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func (p *peFile) u32(off uint64) (uint32, bool) {
	b, ok := p.bytesAt(off, 4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

func (p *peFile) u64(off uint64) (uint64, bool) {
	b, ok := p.bytesAt(off, 8)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// cstring is a NUL-terminated name of at most peMaxName bytes.
func (p *peFile) cstring(off uint64) (string, bool) {
	if off >= uint64(len(p.data)) {
		return "", false
	}
	b := p.data[off:min(uint64(len(p.data)), off+peMaxName)]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i]), true
	}
	return "", false
}

// offset maps a relative virtual address to where its data is: in an image
// the address itself; in a file, through the section that holds it (or the
// headers).
func (p *peFile) offset(rva uint32) (uint64, bool) {
	if p.image {
		return uint64(rva), uint64(rva) < uint64(len(p.data))
	}
	if rva < p.sizeHeaders || len(p.sections) == 0 {
		return uint64(rva), uint64(rva) < uint64(len(p.data))
	}
	for _, s := range p.sections {
		size := s.virtualSize
		if size == 0 {
			size = s.rawSize
		}
		if rva >= s.virtualAddress && rva-s.virtualAddress < size {
			d := rva - s.virtualAddress
			if d >= s.rawSize {
				return 0, false // not stored in the file
			}
			off := uint64(s.rawOffset) + uint64(d)
			return off, off < uint64(len(p.data))
		}
	}
	return 0, false
}

func (p *peFile) rvaU32(rva uint32) (uint32, bool) {
	off, ok := p.offset(rva)
	if !ok {
		return 0, false
	}
	return p.u32(off)
}

func (p *peFile) rvaString(rva uint32) (string, bool) {
	off, ok := p.offset(rva)
	if !ok {
		return "", false
	}
	return p.cstring(off)
}

// dir is a data directory, if present and not empty.
func (p *peFile) dir(i int) (rva, size uint32, ok bool) {
	if i >= len(p.dirs) || p.dirs[i][0] == 0 {
		return 0, 0, false
	}
	return p.dirs[i][0], p.dirs[i][1], true
}

// parsePE parses data as a PE file (image false) or mapped image; nil if
// it is not a PE.
func parsePE(data []byte, image bool, base uint64) *peFile {
	p := &peFile{data: data, image: image, base: base}
	if mz, ok := p.u16(0); !ok || mz != 0x5A4D {
		return nil
	}
	lfanew, ok := p.u32(0x3C)
	if !ok {
		return nil
	}
	if sig, ok := p.u32(uint64(lfanew)); !ok || sig != 0x00004550 {
		return nil
	}
	p.lfanew = lfanew
	h := uint64(lfanew) + 4
	coff, ok := p.bytesAt(h, 20)
	if !ok {
		return nil
	}
	p.machine = binary.LittleEndian.Uint16(coff[0:])
	p.numSections = binary.LittleEndian.Uint16(coff[2:])
	p.timestamp = binary.LittleEndian.Uint32(coff[4:])
	p.symbolTable = binary.LittleEndian.Uint32(coff[8:])
	p.numSymbols = binary.LittleEndian.Uint32(coff[12:])
	p.optSize = binary.LittleEndian.Uint16(coff[16:])
	p.characteristics = binary.LittleEndian.Uint16(coff[18:])
	p.optOffset = uint32(h + 20)
	p.optional()
	p.sectionTable()
	p.importTable()
	p.delayImportTable()
	p.exportTable()
	p.resourceTree()
	p.richHeader()
	p.debugInfo()
	return p
}

func (p *peFile) optional() {
	o := uint64(p.optOffset)
	end := o + uint64(p.optSize)
	opt, ok := p.bytesAt(o, min(uint64(p.optSize), 240))
	if !ok || len(opt) < 2 {
		return
	}
	u16 := func(at int) uint16 {
		if at+2 > len(opt) {
			return 0
		}
		return binary.LittleEndian.Uint16(opt[at:])
	}
	u32 := func(at int) uint32 {
		if at+4 > len(opt) {
			return 0
		}
		return binary.LittleEndian.Uint32(opt[at:])
	}
	u64 := func(at int) uint64 {
		if at+8 > len(opt) {
			return 0
		}
		return binary.LittleEndian.Uint64(opt[at:])
	}
	p.magic = u16(0)
	p.is64 = p.magic == 0x20B
	if len(opt) >= 4 {
		p.linker = [2]uint8{opt[2], opt[3]}
	}
	p.sizeCode, p.sizeInit, p.sizeUninit = u32(4), u32(8), u32(12)
	p.entry, p.baseOfCode = u32(16), u32(20)
	dirAt := 96
	if p.is64 {
		p.imageBase = u64(24)
		p.stackReserve, p.stackCommit, p.heapReserve, p.heapCommit = u64(72), u64(80), u64(88), u64(96)
		p.loaderFlags, p.numRvaSizes = u32(104), u32(108)
		dirAt = 112
	} else {
		p.baseOfData = u32(24)
		p.imageBase = uint64(u32(28))
		p.stackReserve, p.stackCommit, p.heapReserve, p.heapCommit = uint64(u32(72)), uint64(u32(76)), uint64(u32(80)), uint64(u32(84))
		p.loaderFlags, p.numRvaSizes = u32(88), u32(92)
	}
	p.sectionAlign, p.fileAlign = u32(32), u32(36)
	p.osVersion = [2]uint16{u16(40), u16(42)}
	p.imageVersion = [2]uint16{u16(44), u16(46)}
	p.subsystemVersion = [2]uint16{u16(48), u16(50)}
	p.win32Version, p.sizeImage, p.sizeHeaders, p.checksum = u32(52), u32(56), u32(60), u32(64)
	p.subsystem, p.dllCharacteristics = u16(68), u16(70)
	for i := range min(p.numRvaSizes, 16) {
		at := uint64(dirAt) + uint64(i)*8
		if o+at+8 > end {
			break
		}
		va, ok1 := p.u32(o + at)
		size, ok2 := p.u32(o + at + 4)
		if !ok1 || !ok2 {
			break
		}
		p.dirs = append(p.dirs, [2]uint32{va, size})
	}
}

func (p *peFile) sectionTable() {
	at := uint64(p.optOffset) + uint64(p.optSize)
	strTab := uint64(p.symbolTable) + uint64(p.numSymbols)*18
	for i := range min(int(p.numSections), peMaxSections) {
		h, ok := p.bytesAt(at+uint64(i)*40, 40)
		if !ok {
			return
		}
		raw := h[:8]
		if j := bytes.IndexByte(raw, 0); j >= 0 {
			raw = raw[:j]
		}
		s := peSection{name: string(raw)}
		s.fullName = s.name
		// A long name: "/<offset>" into the COFF string table.
		if strings.HasPrefix(s.name, "/") && p.symbolTable != 0 {
			if n, err := strconv.ParseUint(s.name[1:], 10, 32); err == nil {
				if full, ok := p.cstring(strTab + n); ok {
					s.fullName = full
				}
			}
		}
		s.virtualSize = binary.LittleEndian.Uint32(h[8:])
		s.virtualAddress = binary.LittleEndian.Uint32(h[12:])
		s.rawSize = binary.LittleEndian.Uint32(h[16:])
		s.rawOffset = binary.LittleEndian.Uint32(h[20:])
		s.relocations = binary.LittleEndian.Uint32(h[24:])
		s.lineNumbers = binary.LittleEndian.Uint32(h[28:])
		s.numRelocations = binary.LittleEndian.Uint16(h[32:])
		s.numLineNumbers = binary.LittleEndian.Uint16(h[34:])
		s.characteristics = binary.LittleEndian.Uint32(h[36:])
		p.sections = append(p.sections, s)
	}
}

// validDLLName accepts printable names without path separators.
func validDLLName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7E || c == '/' || c == '\\' || c == ':' || c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|' {
			return false
		}
	}
	return true
}

// thunks reads an import lookup table: names, or ordinals.
func (p *peFile) thunks(lookup, addresses uint32, base uint64, total *int) []peFunction {
	size := uint32(4)
	if p.is64 {
		size = 8
	}
	var out []peFunction
	for i := uint32(0); *total < peMaxFunctions; i++ {
		var v uint64
		var ok bool
		off, ok1 := p.offset(lookup + i*size)
		if !ok1 {
			break
		}
		if p.is64 {
			v, ok = p.u64(off)
		} else {
			var w uint32
			w, ok = p.u32(off)
			v = uint64(w)
		}
		if !ok || v == 0 {
			break
		}
		f := peFunction{ordinal: -1, rva: addresses + i*size}
		ordinalFlag := uint64(1) << 31
		if p.is64 {
			ordinalFlag = 1 << 63
		}
		if v&ordinalFlag != 0 {
			f.ordinal = int64(v & 0xFFFF)
		} else {
			if v >= base && base > 0 && v-base < 1<<32 {
				v -= base // an old delay import: a virtual address
			}
			name, ok := p.rvaString(uint32(v) + 2)
			if !ok || name == "" {
				break
			}
			f.name = name
		}
		out = append(out, f)
		*total++
	}
	return out
}

func (p *peFile) importTable() {
	rva, _, ok := p.dir(1)
	if !ok {
		return
	}
	total := 0
	for i := uint32(0); i < peMaxDLLs; i++ {
		off, ok := p.offset(rva + i*20)
		if !ok {
			return
		}
		d, ok := p.bytesAt(off, 20)
		if !ok || bytes.Equal(d, make([]byte, 20)) {
			return
		}
		lookup := binary.LittleEndian.Uint32(d[0:])
		nameRVA := binary.LittleEndian.Uint32(d[12:])
		first := binary.LittleEndian.Uint32(d[16:])
		name, ok := p.rvaString(nameRVA)
		if !ok || !validDLLName(name) {
			continue
		}
		if lookup == 0 {
			lookup = first
		}
		p.imports = append(p.imports, peImport{dll: name, functions: p.thunks(lookup, first, 0, &total)})
	}
}

func (p *peFile) delayImportTable() {
	rva, _, ok := p.dir(13)
	if !ok {
		return
	}
	total := 0
	for i := uint32(0); i < peMaxDLLs; i++ {
		off, ok := p.offset(rva + i*32)
		if !ok {
			return
		}
		d, ok := p.bytesAt(off, 32)
		if !ok || bytes.Equal(d, make([]byte, 32)) {
			return
		}
		attributes := binary.LittleEndian.Uint32(d[0:])
		nameRVA := binary.LittleEndian.Uint32(d[4:])
		iat := binary.LittleEndian.Uint32(d[12:])
		names := binary.LittleEndian.Uint32(d[16:])
		var base uint64
		if attributes&1 == 0 {
			// The first version stored virtual addresses.
			base = p.imageBase
			nameRVA, iat, names = uint32(uint64(nameRVA)-base), uint32(uint64(iat)-base), uint32(uint64(names)-base)
		}
		name, ok := p.rvaString(nameRVA)
		if !ok || !validDLLName(name) {
			continue
		}
		p.delayed = append(p.delayed, peImport{dll: name, functions: p.thunks(names, iat, base, &total)})
	}
}

func (p *peFile) exportTable() {
	rva, size, ok := p.dir(0)
	if !ok {
		return
	}
	off, ok := p.offset(rva)
	if !ok {
		return
	}
	d, ok := p.bytesAt(off, 40)
	if !ok {
		return
	}
	p.hasExports = true
	p.exportTimestamp = binary.LittleEndian.Uint32(d[4:])
	p.dllName, _ = p.rvaString(binary.LittleEndian.Uint32(d[12:]))
	ordBase := binary.LittleEndian.Uint32(d[16:])
	nFuncs := min(binary.LittleEndian.Uint32(d[20:]), peMaxExports)
	nNames := min(binary.LittleEndian.Uint32(d[24:]), peMaxExports)
	funcs := binary.LittleEndian.Uint32(d[28:])
	names := binary.LittleEndian.Uint32(d[32:])
	ordinals := binary.LittleEndian.Uint32(d[36:])
	byIndex := map[uint32]string{}
	for i := range nNames {
		nameRVA, ok1 := p.rvaU32(names + i*4)
		oo, ok2 := p.offset(ordinals + i*2)
		if !ok1 || !ok2 {
			break
		}
		idx, ok := p.u16(oo)
		if !ok {
			break
		}
		if name, ok := p.rvaString(nameRVA); ok {
			if _, dup := byIndex[uint32(idx)]; !dup {
				byIndex[uint32(idx)] = name
			}
		}
	}
	for i := range nFuncs {
		f, ok := p.rvaU32(funcs + i*4)
		if !ok {
			break
		}
		if f == 0 {
			continue
		}
		e := peExport{name: byIndex[i], ordinal: int64(ordBase) + int64(i), rva: f}
		if f >= rva && f-rva < size {
			e.forward, _ = p.rvaString(f)
		}
		p.exports = append(p.exports, e)
	}
}

// resourceName reads a counted UTF-16 name in the resource section.
func (p *peFile) resourceName(base uint64, rel uint32) string {
	n, ok := p.u16(base + uint64(rel))
	if !ok {
		return ""
	}
	b, ok := p.bytesAt(base+uint64(rel)+2, uint64(min(n, peMaxName))*2)
	if !ok {
		return ""
	}
	return utf16String(b)
}

func utf16String(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func (p *peFile) resourceTree() {
	rva, _, ok := p.dir(2)
	if !ok {
		return
	}
	base, ok := p.offset(rva)
	if !ok {
		return
	}
	root, ok := p.bytesAt(base, 16)
	if !ok {
		return
	}
	p.hasResources = true
	p.resourceTimestamp = binary.LittleEndian.Uint32(root[4:])
	p.resourceVersion = [2]uint16{binary.LittleEndian.Uint16(root[8:]), binary.LittleEndian.Uint16(root[10:])}
	seen := map[uint32]bool{}
	var walk func(rel uint32, level int, ids [3]int64, names [3]string)
	walk = func(rel uint32, level int, ids [3]int64, names [3]string) {
		if seen[rel] || len(p.resources) >= peMaxResources {
			return
		}
		seen[rel] = true
		h, ok := p.bytesAt(base+uint64(rel), 16)
		if !ok {
			return
		}
		n := uint32(binary.LittleEndian.Uint16(h[12:])) + uint32(binary.LittleEndian.Uint16(h[14:]))
		for i := range n {
			e, ok := p.bytesAt(base+uint64(rel)+16+uint64(i)*8, 8)
			if !ok || len(p.resources) >= peMaxResources {
				return
			}
			name := binary.LittleEndian.Uint32(e[0:])
			data := binary.LittleEndian.Uint32(e[4:])
			ids[level], names[level] = int64(name&0xFFFF), ""
			if name&(1<<31) != 0 {
				ids[level], names[level] = -1, p.resourceName(base, name&0x7FFFFFFF)
			}
			switch {
			case data&(1<<31) != 0 && level < 2:
				walk(data&0x7FFFFFFF, level+1, ids, names)
			case data&(1<<31) == 0 && level == 2:
				d, ok := p.bytesAt(base+uint64(data), 16)
				if !ok {
					continue
				}
				p.resources = append(p.resources, peResource{
					rva: binary.LittleEndian.Uint32(d[0:]), length: binary.LittleEndian.Uint32(d[4:]),
					typ: ids[0], id: ids[1], language: ids[2], typeName: names[0], idName: names[1], languageName: names[2],
				})
			}
		}
	}
	walk(0, 0, [3]int64{}, [3]string{})
	for _, r := range p.resources {
		if r.typ == 16 { // RT_VERSION
			if off, ok := p.offset(r.rva); ok {
				p.versionInfo(off, uint64(r.length))
			}
		}
	}
}

// versionInfo reads the strings of a VS_VERSIONINFO resource: the
// StringFileInfo block's string tables.
func (p *peFile) versionInfo(off, length uint64) {
	data, ok := p.bytesAt(off, min(length, uint64(len(p.data))-off))
	if !ok {
		return
	}
	// block reads one block: its length, value length, type, key and where
	// its value starts (after the key and padding).
	block := func(at int) (n, valueLen, typ int, key string, value int, ok bool) {
		if at+6 > len(data) {
			return
		}
		n = int(binary.LittleEndian.Uint16(data[at:]))
		valueLen = int(binary.LittleEndian.Uint16(data[at+2:]))
		typ = int(binary.LittleEndian.Uint16(data[at+4:]))
		if n < 6 || at+n > len(data) {
			return
		}
		k := at + 6
		start := k
		for k+1 < at+n && (data[k] != 0 || data[k+1] != 0) {
			k += 2
		}
		key = utf16String(data[start:k])
		value = (k + 2 + 3) &^ 3
		return n, valueLen, typ, key, value, true
	}
	align := func(x int) int { return (x + 3) &^ 3 }
	n, valueLen, _, key, value, ok := block(0)
	if !ok || key != "VS_VERSION_INFO" {
		return
	}
	child := align(value + valueLen)
	for child < n && len(p.version) < peMaxVersion {
		cn, _, _, ckey, cvalue, ok := block(child)
		if !ok {
			return
		}
		if ckey == "StringFileInfo" {
			for t := cvalue; t < child+cn && len(p.version) < peMaxVersion; {
				tn, _, _, _, tvalue, ok := block(t)
				if !ok {
					break
				}
				for s := tvalue; s < t+tn && len(p.version) < peMaxVersion; {
					sn, sv, styp, skey, svalue, ok := block(s)
					if !ok {
						break
					}
					val := ""
					if styp == 1 && sv > 0 {
						end := min(svalue+sv*2, s+sn)
						if end > svalue {
							val = strings.TrimRight(utf16String(data[svalue:end]), "\x00")
						}
					}
					p.version = append(p.version, [2]string{skey, val})
					s = align(s + sn)
				}
				t = align(t + tn)
			}
		}
		child = align(child + cn)
	}
}

// richHeader decodes the Rich header between the DOS stub and the PE
// header: "DanS", padding and (comp id, count) pairs, XORed with a key
// that follows "Rich".
func (p *peFile) richHeader() {
	end := min(int(p.lfanew), len(p.data))
	for at := 0x40; at+8 <= end; at += 4 {
		if binary.LittleEndian.Uint32(p.data[at:]) != 0x68636952 { // "Rich"
			continue
		}
		key := binary.LittleEndian.Uint32(p.data[at+4:])
		for start := at - 4; start >= 0x40; start -= 4 {
			if binary.LittleEndian.Uint32(p.data[start:])^key != 0x536E6144 { // "DanS"
				continue
			}
			r := &peRich{offset: start, length: at - start, key: key, raw: p.data[start:at]}
			r.clear = make([]byte, len(r.raw))
			for i := 0; i+4 <= len(r.raw); i += 4 {
				binary.LittleEndian.PutUint32(r.clear[i:], binary.LittleEndian.Uint32(r.raw[i:])^key)
			}
			for i := 16; i+8 <= len(r.clear) && len(r.entries) < peMaxRichEntries; i += 8 {
				r.entries = append(r.entries, [2]uint32{binary.LittleEndian.Uint32(r.clear[i:]), binary.LittleEndian.Uint32(r.clear[i+4:])})
			}
			p.rich = r
			return
		}
		return
	}
}

// debugInfo reads the PDB path of a CodeView debug entry.
func (p *peFile) debugInfo() {
	rva, size, ok := p.dir(6)
	if !ok {
		return
	}
	for i := uint32(0); i < min(size/28, peMaxDebug); i++ {
		off, ok := p.offset(rva + i*28)
		if !ok {
			return
		}
		e, ok := p.bytesAt(off, 28)
		if !ok {
			return
		}
		if binary.LittleEndian.Uint32(e[12:]) != 2 { // CodeView
			continue
		}
		at := uint64(binary.LittleEndian.Uint32(e[24:]))
		if p.image {
			at = uint64(binary.LittleEndian.Uint32(e[20:]))
		}
		sig, ok := p.bytesAt(at, 4)
		if !ok {
			continue
		}
		switch string(sig) {
		case "RSDS":
			p.pdb, _ = p.cstring(at + 24)
		case "NB10":
			p.pdb, _ = p.cstring(at + 16)
		}
		if p.pdb != "" {
			return
		}
	}
}

// overlay is the data after the last section's raw data in a file.
func (p *peFile) overlay() (offset, size uint64) {
	var end uint64
	for _, s := range p.sections {
		if s.rawSize > 0 {
			end = max(end, uint64(s.rawOffset)+uint64(s.rawSize))
		}
	}
	if end == 0 || end >= uint64(len(p.data)) {
		return 0, 0
	}
	return end, uint64(len(p.data)) - end
}

// calculatedChecksum is the PE checksum of a file: 16-bit words summed with
// carries, the stored checksum skipped, plus the length.
func (p *peFile) calculatedChecksum() uint32 {
	at := uint64(p.optOffset) + 64
	var sum uint64
	for i := uint64(0); i < uint64(len(p.data)); i += 2 {
		if i == at || i == at+2 {
			continue
		}
		w := uint64(p.data[i])
		if i+1 < uint64(len(p.data)) {
			w |= uint64(p.data[i+1]) << 8
		}
		sum += w
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	sum = (sum & 0xFFFF) + (sum >> 16)
	return uint32(sum) + uint32(len(p.data))
}

// imphash is the MD5 input of the import hash: "dll.function" for every
// standard import, lowercase, the extension of .dll, .ocx and .sys names
// removed, ordinals named where known.
func (p *peFile) imphashInput() string {
	var parts []string
	for _, imp := range p.imports {
		dll := strings.ToLower(imp.dll)
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			if strings.HasSuffix(dll, ext) {
				dll = dll[:len(dll)-len(ext)]
				break
			}
		}
		for _, f := range imp.functions {
			name := strings.ToLower(f.name)
			if f.ordinal >= 0 {
				name = ordinalName(dll, f.ordinal)
			}
			parts = append(parts, dll+"."+name)
		}
	}
	return strings.Join(parts, ",")
}

// ordinalName names a function imported by ordinal, as pefile and YARA do.
func ordinalName(dll string, ord int64) string {
	if names := ordinalNames[dll]; names != nil {
		if n, ok := names[uint16(ord)]; ok {
			return strings.ToLower(n)
		}
	}
	return "ord" + strconv.FormatInt(ord, 10)
}
