package evtx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Binary XML (MS-EVEN6) tokens.
const (
	tEOF            = 0x00
	tOpenStart      = 0x01
	tCloseStart     = 0x02
	tCloseEmpty     = 0x03
	tEnd            = 0x04
	tValue          = 0x05
	tAttribute      = 0x06
	tCDATA          = 0x07
	tCharRef        = 0x08
	tEntityRef      = 0x09
	tPITarget       = 0x0A
	tPIData         = 0x0B
	tTemplate       = 0x0C
	tSubstitution   = 0x0D
	tOptionalSubst  = 0x0E
	tFragmentHeader = 0x0F
	hasMore         = 0x40
)

var errBinXML = errors.New("evtx: damaged binary XML")

// Limits that keep a crafted record from recursing or growing without end.
const (
	maxDepth   = 64
	maxNesting = 8
)

// reader decodes binary XML from a chunk between pos and end.
type reader struct {
	c        *chunk
	pos, end int
}

func (p *reader) need(n int) error {
	if n < 0 || p.pos+n > p.end {
		return errBinXML
	}
	return nil
}

func (p *reader) u8() (byte, error) {
	if err := p.need(1); err != nil {
		return 0, err
	}
	p.pos++
	return p.c.b[p.pos-1], nil
}

func (p *reader) u16() (uint16, error) {
	if err := p.need(2); err != nil {
		return 0, err
	}
	p.pos += 2
	return le.Uint16(p.c.b[p.pos-2:]), nil
}

func (p *reader) u32() (uint32, error) {
	if err := p.need(4); err != nil {
		return 0, err
	}
	p.pos += 4
	return le.Uint32(p.c.b[p.pos-4:]), nil
}

// value is one substitution value: its type and raw data.
type value struct {
	typ  byte
	data []byte
	// c and off locate the value in its chunk: nested binary XML refers
	// to names and templates by chunk offsets.
	c   *chunk
	off int
}

// item is a parsed part of binary XML: an element, literal text, a
// substitution of value number sub, or a template instance with its own
// values.
type item struct {
	elem     *telem
	text     string
	sub      int
	optional bool
	inst     *instance
}

type instance struct {
	t      *template
	values []value
}

type telem struct {
	name  string
	attrs []tattr
	kids  []item
}

type tattr struct {
	name  string
	parts []item
}

type template struct{ root []item }

// document reads a fragment (header, then content until EOF) and renders
// it with the substitution values given.
func (p *reader) document(values []value, nest int) (*node, error) {
	items, err := p.content(0)
	if err != nil {
		return nil, err
	}
	root := &node{}
	render(root, items, values, nest)
	return root, nil
}

// content reads tokens until EOF or an element's end, returning the items.
func (p *reader) content(depth int) ([]item, error) {
	if depth > maxDepth {
		return nil, errBinXML
	}
	var out []item
	for {
		tok, err := p.u8()
		if err != nil {
			return out, err
		}
		switch tok &^ hasMore {
		case tEOF, tEnd:
			return out, nil
		case tFragmentHeader:
			if err := p.need(3); err != nil {
				return out, err
			}
			p.pos += 3
		case tOpenStart:
			e, err := p.element(tok, depth)
			if err != nil {
				return out, err
			}
			out = append(out, item{elem: e, sub: -1})
		case tValue:
			s, err := p.literal()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: s, sub: -1})
		case tSubstitution, tOptionalSubst:
			id, err := p.u16()
			if err != nil {
				return out, err
			}
			if _, err := p.u8(); err != nil {
				return out, err
			}
			out = append(out, item{sub: int(id), optional: tok == tOptionalSubst})
		case tCDATA:
			n, err := p.u16()
			if err != nil || p.need(2*int(n)) != nil {
				return out, errBinXML
			}
			out = append(out, item{text: utf16s(p.c.b[p.pos : p.pos+2*int(n)]), sub: -1})
			p.pos += 2 * int(n)
		case tCharRef:
			r, err := p.u16()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: string(rune(r)), sub: -1})
		case tEntityRef:
			name, err := p.name()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: map[string]string{"amp": "&", "lt": "<", "gt": ">", "quot": `"`, "apos": "'"}[name], sub: -1})
		case tPITarget:
			if _, err := p.name(); err != nil {
				return out, err
			}
		case tPIData:
			n, err := p.u16()
			if err != nil || p.need(2*int(n)) != nil {
				return out, errBinXML
			}
			p.pos += 2 * int(n)
		case tTemplate:
			e, err := p.instance(depth)
			if err != nil {
				return out, err
			}
			out = append(out, e...)
		default:
			return out, errBinXML
		}
	}
}

// element reads an element after its open-start token.
func (p *reader) element(tok byte, depth int) (*telem, error) {
	if err := p.need(6); err != nil {
		return nil, err
	}
	p.pos += 6 // dependency identifier, element size
	name, err := p.name()
	if err != nil {
		return nil, err
	}
	e := &telem{name: name}
	if tok&hasMore != 0 {
		if _, err := p.u32(); err != nil { // attribute list size
			return nil, err
		}
	}
	for {
		t, err := p.u8()
		if err != nil {
			return nil, err
		}
		switch t &^ hasMore {
		case tAttribute:
			an, err := p.name()
			if err != nil {
				return nil, err
			}
			parts, err := p.attrValue()
			if err != nil {
				return nil, err
			}
			e.attrs = append(e.attrs, tattr{an, parts})
		case tCloseEmpty:
			return e, nil
		case tCloseStart:
			e.kids, err = p.content(depth + 1)
			return e, err
		default:
			return nil, errBinXML
		}
	}
}

// attrValue reads the value tokens of an attribute (until the next token
// that is not a value or substitution).
func (p *reader) attrValue() ([]item, error) {
	var out []item
	for p.pos < p.end {
		switch p.c.b[p.pos] &^ hasMore {
		case tValue:
			p.pos++
			s, err := p.literal()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: s, sub: -1})
		case tSubstitution, tOptionalSubst:
			p.pos++
			id, err := p.u16()
			if err != nil {
				return out, err
			}
			if _, err := p.u8(); err != nil {
				return out, err
			}
			out = append(out, item{sub: int(id)})
		case tCharRef:
			p.pos++
			r, err := p.u16()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: string(rune(r)), sub: -1})
		case tEntityRef:
			p.pos++
			n, err := p.name()
			if err != nil {
				return out, err
			}
			out = append(out, item{text: map[string]string{"amp": "&", "lt": "<", "gt": ">", "quot": `"`, "apos": "'"}[n], sub: -1})
		default:
			return out, nil
		}
	}
	return out, errBinXML
}

// literal reads a value token's text (a string type).
func (p *reader) literal() (string, error) {
	typ, err := p.u8()
	if err != nil {
		return "", err
	}
	if typ != 0x01 {
		return "", errBinXML
	}
	n, err := p.u16()
	if err != nil || p.need(2*int(n)) != nil {
		return "", errBinXML
	}
	s := utf16s(p.c.b[p.pos : p.pos+2*int(n)])
	p.pos += 2 * int(n)
	return s, nil
}

// name reads a name reference: an offset into the chunk, with the name
// defined right there when it is new.
func (p *reader) name() (string, error) {
	off, err := p.u32()
	if err != nil {
		return "", err
	}
	if int(off) == p.pos {
		n, err := p.c.nameAt(off)
		if err != nil {
			return "", err
		}
		skip := 8 + 2*len(utf16.Encode([]rune(n))) + 2
		if err := p.need(skip); err != nil {
			return "", err
		}
		p.pos += skip
		return n, nil
	}
	return p.c.nameAt(off)
}

func (c *chunk) nameAt(off uint32) (string, error) {
	if n, ok := c.names[off]; ok {
		return n, nil
	}
	o := int(off)
	if o < 0 || o+8 > len(c.b) {
		return "", errBinXML
	}
	n := int(le.Uint16(c.b[o+6:]))
	if o+8+2*n > len(c.b) {
		return "", errBinXML
	}
	s := utf16s(c.b[o+8 : o+8+2*n])
	c.names[off] = s
	return s, nil
}

// instance reads a template instance: the template (defined here when
// new) and its substitution values, and renders it.
func (p *reader) instance(depth int) ([]item, error) {
	if err := p.need(9); err != nil {
		return nil, err
	}
	p.pos += 5 // unknown, template id
	off, _ := p.u32()
	t, ok := p.c.templates[off]
	if int(off) == p.pos {
		if err := p.need(24); err != nil {
			return nil, err
		}
		size := int(le.Uint32(p.c.b[p.pos+20:]))
		body := &reader{c: p.c, pos: p.pos + 24, end: p.pos + 24 + size}
		if size < 0 || body.end > len(p.c.b) || body.end > p.end {
			return nil, errBinXML
		}
		if !ok {
			items, err := body.content(depth + 1)
			if err != nil {
				return nil, err
			}
			t = &template{root: items}
			p.c.templates[off] = t
		}
		p.pos = body.end
	} else if !ok {
		// A template defined earlier in the chunk.
		o := int(off)
		if o < 0 || o+24 > len(p.c.b) {
			return nil, errBinXML
		}
		size := int(le.Uint32(p.c.b[o+20:]))
		body := &reader{c: p.c, pos: o + 24, end: o + 24 + size}
		if size < 0 || body.end > len(p.c.b) {
			return nil, errBinXML
		}
		items, err := body.content(depth + 1)
		if err != nil {
			return nil, err
		}
		t = &template{root: items}
		p.c.templates[off] = t
	}
	count, err := p.u32()
	if err != nil || count > 4096 {
		return nil, errBinXML
	}
	sizes := make([]int, count)
	values := make([]value, count)
	for i := range int(count) {
		n, err := p.u16()
		if err != nil {
			return nil, err
		}
		typ, err := p.u8()
		if err != nil {
			return nil, err
		}
		if _, err := p.u8(); err != nil {
			return nil, err
		}
		sizes[i], values[i].typ = int(n), typ
	}
	for i, n := range sizes {
		if err := p.need(n); err != nil {
			return nil, err
		}
		values[i].data, values[i].c, values[i].off = p.c.b[p.pos:p.pos+n], p.c, p.pos
		p.pos += n
	}
	return []item{{inst: &instance{t, values}, sub: -1}}, nil
}

// render turns parsed items into nodes below parent, substituting values.
func render(parent *node, items []item, values []value, nest int) {
	for _, it := range items {
		switch {
		case it.inst != nil:
			render(parent, it.inst.t.root, it.inst.values, nest)
		case it.elem != nil:
			n := &node{name: it.elem.name}
			for _, a := range it.elem.attrs {
				var s strings.Builder
				for _, part := range a.parts {
					if part.sub >= 0 {
						s.WriteString(format(values, part.sub, nest))
					} else {
						s.WriteString(part.text)
					}
				}
				n.attrs = append(n.attrs, [2]string{a.name, s.String()})
			}
			render(n, it.elem.kids, values, nest)
			parent.kids = append(parent.kids, n)
		case it.sub >= 0:
			if it.sub < len(values) && values[it.sub].typ == 0x21 && nest < maxNesting {
				// Nested binary XML: its elements become children.
				if sub := nested(values[it.sub], nest+1); sub != nil {
					parent.kids = append(parent.kids, sub.kids...)
				}
				continue
			}
			parent.text += format(values, it.sub, nest)
		default:
			parent.text += it.text
		}
	}
}

func nested(v value, nest int) *node {
	if v.c == nil {
		return nil
	}
	p := &reader{c: v.c, pos: v.off, end: v.off + len(v.data)}
	n, err := p.document(nil, nest)
	if err != nil {
		return nil
	}
	return n
}

// format renders substitution value i as text.
func format(values []value, i, nest int) string {
	if i < 0 || i >= len(values) {
		return ""
	}
	v := values[i]
	d := v.data
	if v.typ&0x80 != 0 {
		return array(v.typ&0x7F, d)
	}
	switch v.typ {
	case 0x00:
		return ""
	case 0x01:
		return strings.TrimRight(utf16s(d), "\x00")
	case 0x02:
		return strings.TrimRight(string(d), "\x00")
	case 0x03:
		if len(d) >= 1 {
			return strconv.Itoa(int(int8(d[0])))
		}
	case 0x04:
		if len(d) >= 1 {
			return strconv.Itoa(int(d[0]))
		}
	case 0x05:
		if len(d) >= 2 {
			return strconv.Itoa(int(int16(le.Uint16(d))))
		}
	case 0x06:
		if len(d) >= 2 {
			return strconv.Itoa(int(le.Uint16(d)))
		}
	case 0x07:
		if len(d) >= 4 {
			return strconv.Itoa(int(int32(le.Uint32(d))))
		}
	case 0x08:
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(le.Uint32(d)), 10)
		}
	case 0x09:
		if len(d) >= 8 {
			return strconv.FormatInt(int64(le.Uint64(d)), 10)
		}
	case 0x0A:
		if len(d) >= 8 {
			return strconv.FormatUint(le.Uint64(d), 10)
		}
	case 0x0B:
		if len(d) >= 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(le.Uint32(d))), 'g', -1, 32)
		}
	case 0x0C:
		if len(d) >= 8 {
			return strconv.FormatFloat(math.Float64frombits(le.Uint64(d)), 'g', -1, 64)
		}
	case 0x0D:
		if len(d) >= 4 {
			return strconv.FormatBool(le.Uint32(d) != 0)
		}
	case 0x0E:
		return hex.EncodeToString(d[:min(len(d), 512)])
	case 0x0F:
		if len(d) >= 16 {
			return "{" + guid(d) + "}"
		}
	case 0x10, 0x14, 0x15:
		switch len(d) {
		case 4:
			return fmt.Sprintf("0x%x", le.Uint32(d))
		case 8:
			return fmt.Sprintf("0x%x", le.Uint64(d))
		}
	case 0x11:
		if len(d) >= 8 {
			return stamp(FileTime(le.Uint64(d)))
		}
	case 0x12:
		if len(d) >= 16 {
			t := time.Date(int(le.Uint16(d)), time.Month(le.Uint16(d[2:])), int(le.Uint16(d[6:])), int(le.Uint16(d[8:])), int(le.Uint16(d[10:])), int(le.Uint16(d[12:])), int(le.Uint16(d[14:]))*1e6, time.UTC)
			return stamp(t)
		}
	case 0x13:
		return sid(d)
	case 0x21:
		if n := nested(v, nest+1); n != nil {
			return n.flat()
		}
	}
	return ""
}

// array renders an array value, its items separated by "|".
func array(typ byte, d []byte) string {
	if typ == 0x01 {
		return strings.Join(strings.Split(strings.TrimRight(utf16s(d), "\x00"), "\x00"), "|")
	}
	if typ == 0x02 {
		return strings.Join(strings.Split(strings.TrimRight(string(d), "\x00"), "\x00"), "|")
	}
	size := map[byte]int{0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4, 0x0F: 16, 0x11: 8, 0x12: 16, 0x14: 4, 0x15: 8}[typ]
	if size == 0 {
		return hex.EncodeToString(d[:min(len(d), 512)])
	}
	var parts []string
	for i := 0; i+size <= len(d) && len(parts) < 1024; i += size {
		parts = append(parts, format([]value{{typ: typ, data: d[i : i+size]}}, 0, maxNesting))
	}
	return strings.Join(parts, "|")
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05.0000000")
}

func guid(b []byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", le.Uint32(b), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:16])
}

// sid renders a binary SID as S-1-....
func sid(b []byte) string {
	if len(b) < 8 || 8+4*int(b[1]) > len(b) {
		return ""
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	s := "S-" + strconv.Itoa(int(b[0])) + "-" + strconv.FormatUint(auth, 10)
	for i := range int(b[1]) {
		s += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[8+4*i:])), 10)
	}
	return s
}

func utf16s(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}
