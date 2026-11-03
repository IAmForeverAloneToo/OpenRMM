package yara

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// A strict parser of .NET metadata (ECMA-335 partition II) for the dotnet
// module: the CLI header, metadata streams, the tables YARA's dotnet module
// describes, and method signatures for class and method descriptions. Like
// the PE parser it bounds every read and table.

const (
	netMaxRows       = 1 << 20 // rows of one table that are looked at
	netMaxClasses    = 20000
	netMaxMethods    = 200000 // all classes together
	netMaxParameters = 256
	netMaxGenerics   = 64
	netMaxStrings    = 100000 // user strings, constants, GUIDs and the like
	netMaxTypeDepth  = 16
)

// Table numbers.
const (
	tModule = iota
	tTypeRef
	tTypeDef
	tFieldPtr
	tField
	tMethodPtr
	tMethodDef
	tParamPtr
	tParam
	tInterfaceImpl
	tMemberRef
	tConstant
	tCustomAttribute
	tFieldMarshal
	tDeclSecurity
	tClassLayout
	tFieldLayout
	tStandAloneSig
	tEventMap
	tEventPtr
	tEvent
	tPropertyMap
	tPropertyPtr
	tProperty
	tMethodSemantics
	tMethodImpl
	tModuleRef
	tTypeSpec
	tImplMap
	tFieldRVA
	tEncLog
	tEncMap
	tAssembly
	tAssemblyProcessor
	tAssemblyOS
	tAssemblyRef
	tAssemblyRefProcessor
	tAssemblyRefOS
	tFile
	tExportedType
	tManifestResource
	tNestedClass
	tGenericParam
	tMethodSpec
	tGenericParamConstraint
	numTables
)

// Column kinds: fixed sizes, heap indexes, table indexes and coded
// indexes (by their table lists).
type column struct {
	size  int   // 1, 2 or 4 for constants
	heap  byte  // 's' strings, 'g' GUID, 'b' blob
	table int   // a simple index into this table (-1 none)
	coded []int // a coded index over these tables (-1 for unused tags)
}

var (
	cTypeDefOrRef        = []int{tTypeDef, tTypeRef, tTypeSpec}
	cHasConstant         = []int{tField, tParam, tProperty}
	cHasCustomAttribute  = []int{tMethodDef, tField, tTypeRef, tTypeDef, tParam, tInterfaceImpl, tMemberRef, tModule, tDeclSecurity, tProperty, tEvent, tStandAloneSig, tModuleRef, tTypeSpec, tAssembly, tAssemblyRef, tFile, tExportedType, tManifestResource, tGenericParam, tGenericParamConstraint, tMethodSpec}
	cHasFieldMarshal     = []int{tField, tParam}
	cHasDeclSecurity     = []int{tTypeDef, tMethodDef, tAssembly}
	cMemberRefParent     = []int{tTypeDef, tTypeRef, tModuleRef, tMethodDef, tTypeSpec}
	cHasSemantics        = []int{tEvent, tProperty}
	cMethodDefOrRef      = []int{tMethodDef, tMemberRef}
	cMemberForwarded     = []int{tField, tMethodDef}
	cImplementation      = []int{tFile, tAssemblyRef, tExportedType}
	cCustomAttributeType = []int{-1, -1, tMethodDef, tMemberRef, -1}
	cResolutionScope     = []int{tModule, tModuleRef, tAssemblyRef, tTypeRef}
	cTypeOrMethodDef     = []int{tTypeDef, tMethodDef}
)

func fixed(n int) column   { return column{size: n, table: -1} }
func heap(h byte) column   { return column{heap: h, table: -1} }
func index(t int) column   { return column{table: t} }
func coded(c []int) column { return column{coded: c, table: -1} }

// schema is every table's columns, in order.
var schema = [numTables][]column{
	tModule:                 {fixed(2), heap('s'), heap('g'), heap('g'), heap('g')},
	tTypeRef:                {coded(cResolutionScope), heap('s'), heap('s')},
	tTypeDef:                {fixed(4), heap('s'), heap('s'), coded(cTypeDefOrRef), index(tField), index(tMethodDef)},
	tFieldPtr:               {index(tField)},
	tField:                  {fixed(2), heap('s'), heap('b')},
	tMethodPtr:              {index(tMethodDef)},
	tMethodDef:              {fixed(4), fixed(2), fixed(2), heap('s'), heap('b'), index(tParam)},
	tParamPtr:               {index(tParam)},
	tParam:                  {fixed(2), fixed(2), heap('s')},
	tInterfaceImpl:          {index(tTypeDef), coded(cTypeDefOrRef)},
	tMemberRef:              {coded(cMemberRefParent), heap('s'), heap('b')},
	tConstant:               {fixed(1), fixed(1), coded(cHasConstant), heap('b')},
	tCustomAttribute:        {coded(cHasCustomAttribute), coded(cCustomAttributeType), heap('b')},
	tFieldMarshal:           {coded(cHasFieldMarshal), heap('b')},
	tDeclSecurity:           {fixed(2), coded(cHasDeclSecurity), heap('b')},
	tClassLayout:            {fixed(2), fixed(4), index(tTypeDef)},
	tFieldLayout:            {fixed(4), index(tField)},
	tStandAloneSig:          {heap('b')},
	tEventMap:               {index(tTypeDef), index(tEvent)},
	tEventPtr:               {index(tEvent)},
	tEvent:                  {fixed(2), heap('s'), coded(cTypeDefOrRef)},
	tPropertyMap:            {index(tTypeDef), index(tProperty)},
	tPropertyPtr:            {index(tProperty)},
	tProperty:               {fixed(2), heap('s'), heap('b')},
	tMethodSemantics:        {fixed(2), index(tMethodDef), coded(cHasSemantics)},
	tMethodImpl:             {index(tTypeDef), coded(cMethodDefOrRef), coded(cMethodDefOrRef)},
	tModuleRef:              {heap('s')},
	tTypeSpec:               {heap('b')},
	tImplMap:                {fixed(2), coded(cMemberForwarded), heap('s'), index(tModuleRef)},
	tFieldRVA:               {fixed(4), index(tField)},
	tEncLog:                 {fixed(4), fixed(4)},
	tEncMap:                 {fixed(4)},
	tAssembly:               {fixed(4), fixed(2), fixed(2), fixed(2), fixed(2), fixed(4), heap('b'), heap('s'), heap('s')},
	tAssemblyProcessor:      {fixed(4)},
	tAssemblyOS:             {fixed(4), fixed(4), fixed(4)},
	tAssemblyRef:            {fixed(2), fixed(2), fixed(2), fixed(2), fixed(4), heap('b'), heap('s'), heap('s'), heap('b')},
	tAssemblyRefProcessor:   {fixed(4), index(tAssemblyRef)},
	tAssemblyRefOS:          {fixed(4), fixed(4), fixed(4), index(tAssemblyRef)},
	tFile:                   {fixed(4), heap('s'), heap('b')},
	tExportedType:           {fixed(4), fixed(4), heap('s'), heap('s'), coded(cImplementation)},
	tManifestResource:       {fixed(4), fixed(4), heap('s'), coded(cImplementation)},
	tNestedClass:            {index(tTypeDef), index(tTypeDef)},
	tGenericParam:           {fixed(2), fixed(2), coded(cTypeOrMethodDef), heap('s')},
	tMethodSpec:             {coded(cMethodDefOrRef), heap('b')},
	tGenericParamConstraint: {index(tGenericParam), coded(cTypeDefOrRef)},
}

type netStream struct {
	name         string
	offset, size uint32 // offset from the metadata root
}

type netTable struct {
	rows   uint32
	offset uint64 // of the first row in the data
	widths []int
	size   int // of one row
}

type netFile struct {
	pe       *peFile
	version  string
	root     uint64 // the metadata root's data offset
	streams  []netStream
	strs     []byte // #Strings
	us       []byte // #US
	guids    []byte // #GUID
	blob     []byte // #Blob
	tables   [numTables]netTable
	resource uint64 // data offset of the CLI header's resources
	hasRes   bool
	// Built once, on first use: the enclosing type of nested types, the
	// interfaces of types, and the generic parameters of types and methods.
	indexed  bool
	nested   map[uint32]uint32
	ifaces   map[uint32][]uint32
	genParam map[[2]uint32][]genericParam
}

type genericParam struct {
	number uint32
	name   string
}

// index builds the lookups classes need, in one pass over each table.
func (n *netFile) index() {
	if n.indexed {
		return
	}
	n.indexed = true
	n.nested, n.ifaces, n.genParam = map[uint32]uint32{}, map[uint32][]uint32{}, map[[2]uint32][]genericParam{}
	for i := uint32(1); i <= n.rows(tNestedClass); i++ {
		if child := n.cell(tNestedClass, i, 0); n.nested[child] == 0 {
			n.nested[child] = n.cell(tNestedClass, i, 1)
		}
	}
	for i := uint32(1); i <= n.rows(tInterfaceImpl); i++ {
		c := n.cell(tInterfaceImpl, i, 0)
		if len(n.ifaces[c]) < netMaxGenerics {
			n.ifaces[c] = append(n.ifaces[c], n.cell(tInterfaceImpl, i, 1))
		}
	}
	for i := uint32(1); i <= n.rows(tGenericParam); i++ {
		t, r := decode(cTypeOrMethodDef, n.cell(tGenericParam, i, 2))
		key := [2]uint32{uint32(t), r}
		if t >= 0 && len(n.genParam[key]) < netMaxGenerics {
			n.genParam[key] = append(n.genParam[key], genericParam{n.cell(tGenericParam, i, 0), n.str(n.cell(tGenericParam, i, 3))})
		}
	}
}

// parseDotnet parses a PE's .NET metadata; nil if it has none.
func parseDotnet(p *peFile) *netFile {
	rva, _, ok := p.dir(14)
	if !ok {
		return nil
	}
	off, ok := p.offset(rva)
	if !ok {
		return nil
	}
	cli, ok := p.bytesAt(off, 72)
	if !ok {
		return nil
	}
	n := &netFile{pe: p}
	mdRVA := binary.LittleEndian.Uint32(cli[8:])
	if resRVA := binary.LittleEndian.Uint32(cli[24:]); resRVA != 0 {
		n.resource, n.hasRes = p.offset(resRVA)
	}
	root, ok := p.offset(mdRVA)
	if !ok {
		return nil
	}
	if sig, ok := p.u32(root); !ok || sig != 0x424A5342 { // BSJB
		return nil
	}
	n.root = root
	vlen, ok := p.u32(root + 12)
	if !ok || vlen > 256 {
		return nil
	}
	v, ok := p.bytesAt(root+16, uint64(vlen))
	if !ok {
		return nil
	}
	n.version = strings.TrimRight(string(v), "\x00")
	at := root + 16 + uint64(vlen)
	count, ok := p.u16(at + 2)
	if !ok {
		return nil
	}
	at += 4
	for range min(count, 16) {
		h, ok := p.bytesAt(at, 8)
		if !ok {
			break
		}
		name, ok := p.cstring(at + 8)
		if !ok || len(name) > 32 {
			break
		}
		s := netStream{name: name, offset: binary.LittleEndian.Uint32(h[0:]), size: binary.LittleEndian.Uint32(h[4:])}
		n.streams = append(n.streams, s)
		at += 8 + uint64((len(name)+4)&^3)
		data, ok := p.bytesAt(root+uint64(s.offset), uint64(s.size))
		if !ok {
			continue
		}
		switch name {
		case "#Strings":
			n.strs = data
		case "#US":
			n.us = data
		case "#GUID":
			n.guids = data
		case "#Blob":
			n.blob = data
		}
	}
	for _, s := range n.streams {
		if s.name == "#~" || s.name == "#-" {
			n.tableStream(root + uint64(s.offset))
			break
		}
	}
	return n
}

// tableStream reads the table stream header and lays out every table.
func (n *netFile) tableStream(at uint64) {
	p := n.pe
	h, ok := p.bytesAt(at, 24)
	if !ok {
		return
	}
	heapSizes := h[6]
	valid := binary.LittleEndian.Uint64(h[8:])
	at += 24
	for t := range 64 {
		if valid&(1<<t) == 0 {
			continue
		}
		rows, ok := p.u32(at)
		if !ok {
			return
		}
		if t < numTables {
			n.tables[t].rows = rows
		}
		at += 4
	}
	heapWidth := map[byte]int{'s': 2, 'g': 2, 'b': 2}
	if heapSizes&1 != 0 {
		heapWidth['s'] = 4
	}
	if heapSizes&2 != 0 {
		heapWidth['g'] = 4
	}
	if heapSizes&4 != 0 {
		heapWidth['b'] = 4
	}
	width := func(c column) int {
		switch {
		case c.size > 0:
			return c.size
		case c.heap != 0:
			return heapWidth[c.heap]
		case c.coded != nil:
			bits := 0
			for 1<<bits < len(c.coded) {
				bits++
			}
			var most uint32
			for _, t := range c.coded {
				if t >= 0 {
					most = max(most, n.tables[t].rows)
				}
			}
			if most < 1<<(16-bits) {
				return 2
			}
			return 4
		default:
			if n.tables[c.table].rows < 1<<16 {
				return 2
			}
			return 4
		}
	}
	for t := range numTables {
		tb := &n.tables[t]
		for _, c := range schema[t] {
			w := width(c)
			tb.widths = append(tb.widths, w)
			tb.size += w
		}
		tb.offset = at
		at += uint64(tb.rows) * uint64(tb.size)
	}
	// Rows beyond the data are not there: a damaged count must not make
	// loops run over nothing.
	for t := range numTables {
		tb := &n.tables[t]
		if tb.offset >= uint64(len(p.data)) {
			tb.rows = 0
		} else if fit := (uint64(len(p.data)) - tb.offset) / uint64(tb.size); uint64(tb.rows) > fit {
			tb.rows = uint32(fit)
		}
	}
}

// cell is column col of row (from 1) of a table, 0 when unreadable.
func (n *netFile) cell(t int, row uint32, col int) uint32 {
	tb := &n.tables[t]
	if row == 0 || row > tb.rows || col >= len(tb.widths) {
		return 0
	}
	at := tb.offset + uint64(row-1)*uint64(tb.size)
	for i := range col {
		at += uint64(tb.widths[i])
	}
	if tb.widths[col] == 1 {
		b, ok := n.pe.bytesAt(at, 1)
		if !ok {
			return 0
		}
		return uint32(b[0])
	}
	if tb.widths[col] == 2 {
		v, _ := n.pe.u16(at)
		return uint32(v)
	}
	v, _ := n.pe.u32(at)
	return v
}

func (n *netFile) rows(t int) uint32 { return min(n.tables[t].rows, netMaxRows) }

// str is a #Strings entry.
func (n *netFile) str(i uint32) string {
	if uint64(i) >= uint64(len(n.strs)) {
		return ""
	}
	b := n.strs[i:min(len(n.strs), int(i)+peMaxName)]
	for j, c := range b {
		if c == 0 {
			return string(b[:j])
		}
	}
	return ""
}

// blobAt is a #Blob entry (after its compressed length).
func (n *netFile) blobAt(i uint32) []byte {
	if uint64(i) >= uint64(len(n.blob)) {
		return nil
	}
	size, used, ok := compressed(n.blob[i:])
	if !ok || uint64(i)+uint64(used)+uint64(size) > uint64(len(n.blob)) {
		return nil
	}
	return n.blob[int(i)+used : int(i)+used+int(size)]
}

// compressed reads an ECMA-335 compressed unsigned integer.
func compressed(b []byte) (v uint32, n int, ok bool) {
	switch {
	case len(b) >= 1 && b[0]&0x80 == 0:
		return uint32(b[0]), 1, true
	case len(b) >= 2 && b[0]&0xC0 == 0x80:
		return uint32(b[0]&0x3F)<<8 | uint32(b[1]), 2, true
	case len(b) >= 4 && b[0]&0xE0 == 0xC0:
		return uint32(b[0]&0x1F)<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), 4, true
	}
	return 0, 0, false
}

// decode splits a coded index into its table and row.
func decode(c []int, v uint32) (table int, row uint32) {
	bits := 0
	for 1<<bits < len(c) {
		bits++
	}
	tag := int(v & (1<<bits - 1))
	if tag >= len(c) {
		return -1, 0
	}
	return c[tag], v >> bits
}

// guid formats a #GUID entry (from 1).
func (n *netFile) guid(i uint32) string {
	if i == 0 || uint64(i)*16 > uint64(len(n.guids)) {
		return ""
	}
	g := n.guids[(i-1)*16 : i*16]
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(g), binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:16])
}

func (n *netFile) guidList() []string {
	var out []string
	for i := uint32(1); uint64(i)*16 <= uint64(len(n.guids)) && len(out) < netMaxStrings; i++ {
		out = append(out, n.guid(i))
	}
	return out
}

// userStrings are the #US heap's strings (UTF-16 bytes, without the final
// flag byte), as YARA lists them.
func (n *netFile) userStrings() []string {
	var out []string
	for at := 1; at < len(n.us) && len(out) < netMaxStrings; {
		size, used, ok := compressed(n.us[at:])
		if !ok || at+used+int(size) > len(n.us) {
			break
		}
		if size > 1 {
			out = append(out, string(n.us[at+used:at+used+int(size)-1]))
		}
		at += used + int(size)
	}
	return out
}

// typeName names a TypeDef, TypeRef or TypeSpec row, with its namespace and
// enclosing types.
func (n *netFile) typeName(table int, row uint32, depth int) string {
	if depth > netMaxTypeDepth {
		return ""
	}
	switch table {
	case tTypeDef:
		name, ns := n.str(n.cell(tTypeDef, row, 1)), n.str(n.cell(tTypeDef, row, 2))
		if outer := n.enclosing(row); outer != 0 {
			return n.typeName(tTypeDef, outer, depth+1) + "." + name
		}
		return dotted(ns, name)
	case tTypeRef:
		name, ns := n.str(n.cell(tTypeRef, row, 1)), n.str(n.cell(tTypeRef, row, 2))
		if t, r := decode(cResolutionScope, n.cell(tTypeRef, row, 0)); t == tTypeRef && r != row {
			return n.typeName(tTypeRef, r, depth+1) + "." + name
		}
		return dotted(ns, name)
	case tTypeSpec:
		sig := n.blobAt(n.cell(tTypeSpec, row, 0))
		s := &sigReader{n: n, b: sig}
		return s.typ(depth + 1)
	}
	return ""
}

func dotted(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "." + name
}

// enclosing is the TypeDef a nested TypeDef is declared in, 0 if none.
func (n *netFile) enclosing(row uint32) uint32 {
	n.index()
	return n.nested[row]
}

// sigReader decodes signature blobs into type names, as YARA writes them.
type sigReader struct {
	n *netFile
	b []byte
	// generic parameter names of the class and the method, for VAR and
	// MVAR.
	classGenerics, methodGenerics []string
	bad                           bool
}

func (s *sigReader) byte() byte {
	if len(s.b) == 0 {
		s.bad = true
		return 0
	}
	c := s.b[0]
	s.b = s.b[1:]
	return c
}

func (s *sigReader) number() uint32 {
	v, used, ok := compressed(s.b)
	if !ok {
		s.bad = true
		return 0
	}
	s.b = s.b[used:]
	return v
}

// typeDefOrRef is a TypeDefOrRefEncoded token.
func (s *sigReader) typeDefOrRef(depth int) string {
	v := s.number()
	t, r := decode(cTypeDefOrRef, v)
	return s.n.typeName(t, r, depth+1)
}

var primitives = map[byte]string{
	0x01: "void", 0x02: "bool", 0x03: "char", 0x04: "sbyte", 0x05: "byte", 0x06: "short", 0x07: "ushort",
	0x08: "int", 0x09: "uint", 0x0A: "long", 0x0B: "ulong", 0x0C: "float", 0x0D: "double", 0x0E: "string",
	0x16: "TypedReference", 0x18: "IntPtr", 0x19: "UIntPtr", 0x1C: "object",
}

func (s *sigReader) typ(depth int) string {
	if depth > netMaxTypeDepth || s.bad {
		s.bad = true
		return ""
	}
	c := s.byte()
	if name, ok := primitives[c]; ok {
		return name
	}
	switch c {
	case 0x0F: // pointer
		return "Ptr<" + s.typ(depth+1) + ">"
	case 0x10: // by reference
		return "ref " + s.typ(depth+1)
	case 0x11, 0x12: // value type, class
		return s.typeDefOrRef(depth)
	case 0x13, 0x1E: // generic parameter of the class, of the method
		i := s.number()
		names := s.classGenerics
		if c == 0x1E {
			names = s.methodGenerics
		}
		if int(i) < len(names) {
			return names[i]
		}
		return ""
	case 0x14: // array
		elem := s.typ(depth + 1)
		rank := s.number()
		sizes := s.number()
		for range min(sizes, 64) {
			s.number()
		}
		lows := s.number()
		for range min(lows, 64) {
			s.number()
		}
		if rank == 0 || rank > 32 {
			s.bad = true
			return ""
		}
		return elem + "[" + strings.Repeat(",", int(rank)-1) + "]"
	case 0x15: // generic instance
		s.byte()
		base := s.typeDefOrRef(depth)
		count := s.number()
		var args []string
		for range min(count, netMaxGenerics) {
			args = append(args, s.typ(depth+1))
		}
		// List`1 with its arguments is written List<string>.
		if i := strings.LastIndexByte(base, '`'); i > 0 {
			base = base[:i]
		}
		return base + "<" + strings.Join(args, ",") + ">"
	case 0x1B: // function pointer
		ret, params := s.method(depth + 1)
		return "FnPtr<" + ret + "(" + strings.Join(params, ", ") + ")>"
	case 0x1D: // single-dimensional array
		return s.typ(depth+1) + "[]"
	case 0x1F, 0x20: // custom modifiers: the modified type follows
		s.typeDefOrRef(depth)
		return s.typ(depth + 1)
	case 0x45: // pinned
		return s.typ(depth + 1)
	}
	s.bad = true
	return ""
}

// method reads a method signature: the return type and parameter types.
func (s *sigReader) method(depth int) (string, []string) {
	conv := s.byte()
	if conv&0x10 != 0 { // generic
		s.number()
	}
	count := s.number()
	ret := s.typ(depth)
	var params []string
	for range min(count, netMaxParameters) {
		if len(s.b) > 0 && s.b[0] == 0x41 { // sentinel of a vararg call
			s.b = s.b[1:]
		}
		params = append(params, s.typ(depth))
		if s.bad {
			break
		}
	}
	return ret, params
}

type netParam struct{ name, typ string }

type netMethod struct {
	name, visibility, ret            string
	static, virtual, final, abstract bool
	params                           []netParam
	generics                         []string
}

type netClass struct {
	fullname, name, namespace, visibility, kind string
	abstract, sealed                            bool
	generics, bases                             []string
	methods                                     []netMethod
}

var memberVisibility = []string{"private", "private", "private protected", "internal", "protected", "protected internal", "public", "private"}

// Type visibility: not public, public, then nested public, private, family,
// assembly, family and assembly, family or assembly.
var typeVisibility = []string{"internal", "public", "public", "private", "protected", "internal", "private protected", "protected internal"}

// generics are the names of a TypeDef's or MethodDef's generic parameters.
func (n *netFile) generics(owner int, row uint32) []string {
	n.index()
	list := n.genParam[[2]uint32{uint32(owner), row}]
	out := make([]string, len(list))
	for _, g := range list {
		if int(g.number) < len(out) {
			out[g.number] = g.name
		}
	}
	return out
}

// classes describes the TypeDefs with their methods (the <Module> type
// excluded).
func (n *netFile) classes() []netClass {
	var out []netClass
	types := n.rows(tTypeDef)
	methodsLeft := netMaxMethods
	for row := uint32(1); row <= types && len(out) < netMaxClasses; row++ {
		name := n.str(n.cell(tTypeDef, row, 1))
		if name == "<Module>" {
			continue
		}
		flags := n.cell(tTypeDef, row, 0)
		c := netClass{
			fullname: n.typeName(tTypeDef, row, 0), name: name, namespace: n.str(n.cell(tTypeDef, row, 2)),
			visibility: typeVisibility[flags&7], kind: "class",
			abstract: flags&0x80 != 0, sealed: flags&0x100 != 0, generics: n.generics(tTypeDef, row),
		}
		if flags&0x20 != 0 {
			c.kind = "interface"
		}
		if t, r := decode(cTypeDefOrRef, n.cell(tTypeDef, row, 3)); r != 0 {
			c.bases = append(c.bases, n.typeName(t, r, 0))
		}
		n.index()
		for _, v := range n.ifaces[row] {
			t, r := decode(cTypeDefOrRef, v)
			c.bases = append(c.bases, n.typeName(t, r, 0))
		}
		first := n.cell(tTypeDef, row, 5)
		last := n.rows(tMethodDef) + 1
		if row < types {
			last = n.cell(tTypeDef, row+1, 5)
		}
		for m := first; m < last && m <= n.rows(tMethodDef) && methodsLeft > 0; m++ {
			methodsLeft--
			c.methods = append(c.methods, n.method(m, c.generics))
		}
		out = append(out, c)
	}
	return out
}

func (n *netFile) method(row uint32, classGenerics []string) netMethod {
	flags := n.cell(tMethodDef, row, 2)
	m := netMethod{
		name: n.str(n.cell(tMethodDef, row, 3)), visibility: memberVisibility[flags&7],
		static: flags&0x10 != 0, virtual: flags&0x40 != 0, final: flags&0x20 != 0, abstract: flags&0x400 != 0,
		generics: n.generics(tMethodDef, row),
	}
	s := &sigReader{n: n, b: n.blobAt(n.cell(tMethodDef, row, 4)), classGenerics: classGenerics, methodGenerics: m.generics}
	ret, types := s.method(0)
	m.ret = ret
	// Parameter names come from the Param table (sequence 1..n; 0 is the
	// return value).
	names := map[uint32]string{}
	first := n.cell(tMethodDef, row, 5)
	last := n.rows(tParam) + 1
	if row < n.rows(tMethodDef) {
		last = n.cell(tMethodDef, row+1, 5)
	}
	for p := first; p < last && p <= n.rows(tParam) && p-first < netMaxParameters; p++ {
		names[n.cell(tParam, p, 1)] = n.str(n.cell(tParam, p, 2))
	}
	for i, t := range types {
		m.params = append(m.params, netParam{name: names[uint32(i+1)], typ: t})
	}
	return m
}

type netAssemblyRef struct {
	version [4]int64
	token   string
	name    string
}

type netResource struct {
	offset, length int64
	name           string
}

func (n *netFile) assemblyRefs() []netAssemblyRef {
	var out []netAssemblyRef
	for i := uint32(1); i <= n.rows(tAssemblyRef) && len(out) < netMaxStrings; i++ {
		out = append(out, netAssemblyRef{
			version: [4]int64{int64(n.cell(tAssemblyRef, i, 0)), int64(n.cell(tAssemblyRef, i, 1)), int64(n.cell(tAssemblyRef, i, 2)), int64(n.cell(tAssemblyRef, i, 3))},
			token:   string(n.blobAt(n.cell(tAssemblyRef, i, 5))),
			name:    n.str(n.cell(tAssemblyRef, i, 6)),
		})
	}
	return out
}

// resources are the embedded manifest resources: their data follows a
// length in the CLI header's resources.
func (n *netFile) resources() []netResource {
	var out []netResource
	for i := uint32(1); i <= n.rows(tManifestResource) && len(out) < netMaxStrings; i++ {
		if n.cell(tManifestResource, i, 3) != 0 || !n.hasRes {
			continue // in another file or assembly
		}
		at := n.resource + uint64(n.cell(tManifestResource, i, 0))
		length, ok := n.pe.u32(at)
		if !ok || uint64(length) > uint64(len(n.pe.data))-at-4 {
			continue
		}
		out = append(out, netResource{offset: n.pe.address(at + 4), length: int64(length), name: n.str(n.cell(tManifestResource, i, 2))})
	}
	return out
}

// typelib is the assembly's GuidAttribute value.
func (n *netFile) typelib() string {
	for i := uint32(1); i <= n.rows(tCustomAttribute); i++ {
		if t, _ := decode(cHasCustomAttribute, n.cell(tCustomAttribute, i, 0)); t != tAssembly {
			continue
		}
		t, r := decode(cCustomAttributeType, n.cell(tCustomAttribute, i, 1))
		if t != tMemberRef {
			continue
		}
		pt, pr := decode(cMemberRefParent, n.cell(tMemberRef, r, 0))
		if pt != tTypeRef || n.str(n.cell(tTypeRef, pr, 1)) != "GuidAttribute" {
			continue
		}
		v := n.blobAt(n.cell(tCustomAttribute, i, 2))
		if len(v) < 3 || v[0] != 1 || v[1] != 0 {
			continue
		}
		size, used, ok := compressed(v[2:])
		if ok && 2+used+int(size) <= len(v) {
			return string(v[2+used : 2+used+int(size)])
		}
	}
	return ""
}

func (n *netFile) constants() []string {
	var out []string
	for i := uint32(1); i <= n.rows(tConstant) && len(out) < netMaxStrings; i++ {
		out = append(out, string(n.blobAt(n.cell(tConstant, i, 3))))
	}
	return out
}

func (n *netFile) fieldOffsets() []int64 {
	var out []int64
	for i := uint32(1); i <= n.rows(tFieldLayout) && len(out) < netMaxStrings; i++ {
		out = append(out, int64(n.cell(tFieldLayout, i, 0)))
	}
	return out
}

func (n *netFile) moduleRefs() []string {
	var out []string
	for i := uint32(1); i <= n.rows(tModuleRef) && len(out) < netMaxStrings; i++ {
		out = append(out, n.str(n.cell(tModuleRef, i, 0)))
	}
	return out
}
