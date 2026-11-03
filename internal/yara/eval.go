package yara

import (
	"encoding/binary"
	"slices"
	"strings"
)

// value is a condition value: undefined, an integer, a decimal, a boolean,
// text, or module data (a structure, array or dictionary; a regular
// expression passed to a module function).
type value struct {
	kind byte // 0 undefined, 'i', 'f', 'b', 's', 'o', 'r'
	i    int64
	f    float64
	s    string
	o    any
}

var undefined = value{}

func intV(i int64) value     { return value{kind: 'i', i: i} }
func floatV(f float64) value { return value{kind: 'f', f: f} }

// num is a number as a decimal.
func (v value) num() float64 {
	if v.kind == 'f' {
		return v.f
	}
	return float64(v.i)
}
func boolV(b bool) value {
	if b {
		return value{kind: 'b', i: 1}
	}
	return value{kind: 'b'}
}

// truth is a value in a boolean context: undefined is false.
func (v value) truth() bool {
	switch v.kind {
	case 'i', 'b':
		return v.i != 0
	case 'f':
		return v.f != 0
	case 's':
		return v.s != ""
	case 'o':
		return true
	}
	return false
}

// maxLoop bounds the iterations of one for expression.
const maxLoop = 100_000

type evaluator struct {
	rs      *Rules
	hits    [][]hit
	blocks  []Block
	size    int64
	results map[*Rule]bool
	index   map[*pattern]int
	vars    []binding
	// mods holds each module's data for this scan; target is what the
	// modules describe.
	mods   map[*module]any
	target Target
	// anon is the string a for-of body refers to as $, #, @ and !.
	anon []*pattern
}

type binding struct {
	name string
	v    value
}

func (e *evaluator) rule(r *Rule) bool {
	if v, ok := e.results[r]; ok {
		return v
	}
	v := e.eval(r.cond).truth()
	e.results[r] = v
	return v
}

func (e *evaluator) hitsOf(p *pattern) []hit { return e.hits[e.index[p]] }

// eval computes a parsed condition over the scan's matches; it walks the
// expression tree and executes nothing.
func (e *evaluator) eval(n node) value {
	switch x := n.(type) {
	case boolLit:
		return boolV(x.v)
	case intLit:
		return intV(x.v)
	case floatLit:
		return floatV(x.v)
	case modRef, fieldN, indexN, callN, entryN:
		return e.evalModule(n)
	case strLit:
		return value{kind: 's', s: x.v}
	case filesizeN:
		if e.size < 0 {
			return undefined
		}
		return intV(e.size)
	case strMatch:
		return boolV(len(e.hitsOf(x.p)) > 0)
	case strCount:
		return intV(int64(len(e.hitsOf(x.p))))
	case strAt:
		at := e.eval(x.x)
		if at.kind != 'i' {
			return undefined
		}
		for _, h := range e.hitsOf(x.p) {
			if int64(h.off) == at.i {
				return boolV(true)
			}
		}
		return boolV(false)
	case strIn:
		lo, hi := e.eval(x.x), e.eval(x.y)
		if lo.kind != 'i' || hi.kind != 'i' {
			return undefined
		}
		return boolV(inRange(e.hitsOf(x.p), lo.i, hi.i) > 0)
	case strOffset:
		return e.offset(e.hitsOf(x.p), x.i, x.length)
	case intRead:
		return e.read(x)
	case ruleRef:
		return boolV(e.rule(x.r))
	case varRef:
		for i := len(e.vars) - 1; i >= 0; i-- {
			if e.vars[i].name == x.name {
				return e.vars[i].v
			}
		}
		return undefined
	case anonRef:
		if len(e.anon) == 0 {
			return undefined
		}
		hs := e.hitsOf(e.anon[len(e.anon)-1])
		switch {
		case x.kind == "$" && x.at != nil:
			at := e.eval(x.at)
			if at.kind != 'i' {
				return undefined
			}
			return boolV(inRange(hs, at.i, at.i) > 0)
		case x.kind == "$" && x.in != nil:
			lo, hi := e.eval(x.in.x), e.eval(x.in.y)
			if lo.kind != 'i' || hi.kind != 'i' {
				return undefined
			}
			return boolV(inRange(hs, lo.i, hi.i) > 0)
		case x.kind == "$":
			return boolV(len(hs) > 0)
		case x.kind == "#":
			return intV(int64(len(hs)))
		}
		return e.offset(hs, x.i, x.kind == "!")
	case unary:
		v := e.eval(x.x)
		switch x.op {
		case "not":
			if v.kind == 0 {
				return undefined
			}
			return boolV(!v.truth())
		case "defined":
			return boolV(v.kind != 0)
		case "-":
			switch v.kind {
			case 'i':
				return intV(-v.i)
			case 'f':
				return floatV(-v.f)
			}
			return undefined
		case "~":
			if v.kind != 'i' {
				return undefined
			}
			return intV(^v.i)
		}
	case binop:
		return e.binop(x)
	case *ofExpr:
		return e.of(x, nil)
	case forOf:
		return e.of(x.of, x.body)
	case forIn:
		return e.forIn(x)
	}
	return undefined
}

func inRange(hs []hit, lo, hi int64) int {
	n := 0
	for _, h := range hs {
		if int64(h.off) >= lo && int64(h.off) <= hi {
			n++
		}
	}
	return n
}

// offset is @a[i] (or !a[i] for the length); i counts from 1.
func (e *evaluator) offset(hs []hit, in node, length bool) value {
	i := e.eval(in)
	if i.kind != 'i' || i.i < 1 || i.i > int64(len(hs)) {
		return undefined
	}
	h := hs[i.i-1]
	if length {
		return intV(int64(h.n))
	}
	return intV(int64(h.off))
}

// read is uint8..int32be(x) at an address of the scanned data.
func (e *evaluator) read(x intRead) value {
	at := e.eval(x.x)
	if at.kind != 'i' || at.i < 0 {
		return undefined
	}
	for _, b := range e.blocks {
		if uint64(at.i) < b.Base || uint64(at.i)-b.Base+uint64(x.size) > uint64(len(b.Data)) {
			continue
		}
		d := b.Data[uint64(at.i)-b.Base:]
		var u uint64
		switch x.size {
		case 1:
			u = uint64(d[0])
		case 2:
			if x.big {
				u = uint64(binary.BigEndian.Uint16(d))
			} else {
				u = uint64(binary.LittleEndian.Uint16(d))
			}
		case 4:
			if x.big {
				u = uint64(binary.BigEndian.Uint32(d))
			} else {
				u = uint64(binary.LittleEndian.Uint32(d))
			}
		}
		if x.signed {
			shift := 64 - 8*uint(x.size)
			return intV(int64(u<<shift) >> shift)
		}
		return intV(int64(u))
	}
	return undefined
}

func (e *evaluator) binop(x binop) value {
	switch x.op {
	case "and":
		return boolV(e.eval(x.x).truth() && e.eval(x.y).truth())
	case "or":
		return boolV(e.eval(x.x).truth() || e.eval(x.y).truth())
	case "countin":
		c := x.x.(strCount)
		r := x.y.(rangeN)
		lo, hi := e.eval(r.x), e.eval(r.y)
		if lo.kind != 'i' || hi.kind != 'i' {
			return undefined
		}
		return intV(int64(inRange(e.hitsOf(c.p), lo.i, hi.i)))
	case "matches":
		a := e.eval(x.x)
		if a.kind != 's' {
			return undefined
		}
		p := x.y.(*pattern)
		return boolV(p.re.FindReaderIndex(&byteReader{b: []byte(a.s)}) != nil)
	}
	a, b := e.eval(x.x), e.eval(x.y)
	if a.kind == 0 || b.kind == 0 || a.kind == 'o' || b.kind == 'o' {
		return undefined
	}
	if a.kind == 'f' || b.kind == 'f' {
		if a.kind == 's' || b.kind == 's' {
			return undefined
		}
		return floatOp(x.op, a.num(), b.num())
	}
	if a.kind == 's' || b.kind == 's' {
		if a.kind != 's' || b.kind != 's' {
			return undefined
		}
		la, lb := strings.ToLower(a.s), strings.ToLower(b.s)
		switch x.op {
		case "==":
			return boolV(a.s == b.s)
		case "!=":
			return boolV(a.s != b.s)
		case "<":
			return boolV(a.s < b.s)
		case ">":
			return boolV(a.s > b.s)
		case "<=":
			return boolV(a.s <= b.s)
		case ">=":
			return boolV(a.s >= b.s)
		case "contains":
			return boolV(strings.Contains(a.s, b.s))
		case "icontains":
			return boolV(strings.Contains(la, lb))
		case "startswith":
			return boolV(strings.HasPrefix(a.s, b.s))
		case "istartswith":
			return boolV(strings.HasPrefix(la, lb))
		case "endswith":
			return boolV(strings.HasSuffix(a.s, b.s))
		case "iendswith":
			return boolV(strings.HasSuffix(la, lb))
		case "iequals":
			return boolV(la == lb)
		}
		return undefined
	}
	p, q := a.i, b.i
	switch x.op {
	case "==":
		return boolV(p == q)
	case "!=":
		return boolV(p != q)
	case "<":
		return boolV(p < q)
	case ">":
		return boolV(p > q)
	case "<=":
		return boolV(p <= q)
	case ">=":
		return boolV(p >= q)
	case "+":
		return intV(p + q)
	case "-":
		return intV(p - q)
	case "*":
		return intV(p * q)
	case "\\":
		if q == 0 {
			return undefined
		}
		return intV(p / q)
	case "%":
		if q == 0 {
			return undefined
		}
		return intV(p % q)
	case "&":
		return intV(p & q)
	case "|":
		return intV(p | q)
	case "^":
		return intV(p ^ q)
	case "<<":
		if q < 0 || q > 63 {
			return intV(0)
		}
		return intV(p << uint(q))
	case ">>":
		if q < 0 || q > 63 {
			return intV(0)
		}
		return intV(p >> uint(q))
	}
	return undefined
}

// floatOp is an arithmetic or comparison with a decimal operand; integer
// operators (%, bit operations, shifts) are undefined on decimals.
func floatOp(op string, p, q float64) value {
	switch op {
	case "==":
		return boolV(p == q)
	case "!=":
		return boolV(p != q)
	case "<":
		return boolV(p < q)
	case ">":
		return boolV(p > q)
	case "<=":
		return boolV(p <= q)
	case ">=":
		return boolV(p >= q)
	case "+":
		return floatV(p + q)
	case "-":
		return floatV(p - q)
	case "*":
		return floatV(p * q)
	case "\\":
		if q == 0 {
			return undefined
		}
		return floatV(p / q)
	}
	return undefined
}

// quantified applies a quantifier to how many of total items held.
func (e *evaluator) quantified(quant node, all, none, percent bool, held, total int) value {
	switch {
	case all:
		return boolV(held == total)
	case none:
		return boolV(held == 0)
	case quant == nil:
		return boolV(held >= 1)
	}
	q := e.eval(quant)
	if q.kind != 'i' {
		return undefined
	}
	need := q.i
	if percent {
		need = (q.i*int64(total) + 99) / 100
	}
	return boolV(int64(held) >= need)
}

// of evaluates "N of (set)", and with a body "for N of (set) : (body)".
func (e *evaluator) of(o *ofExpr, body node) value {
	held, total := 0, 0
	if o.rules != nil {
		total = len(o.rules)
		for _, r := range o.rules {
			if e.rule(r) {
				held++
			}
		}
	} else {
		total = len(o.set)
		for _, p := range o.set {
			ok := false
			switch {
			case body != nil:
				e.anon = append(e.anon, p)
				ok = e.eval(body).truth()
				e.anon = e.anon[:len(e.anon)-1]
			case o.in != nil:
				lo, hi := e.eval(o.in.x), e.eval(o.in.y)
				ok = lo.kind == 'i' && hi.kind == 'i' && inRange(e.hitsOf(p), lo.i, hi.i) > 0
			default:
				ok = len(e.hitsOf(p)) > 0
			}
			if ok {
				held++
			}
		}
	}
	return e.quantified(o.quant, o.all, o.none, o.percent, held, total)
}

func (e *evaluator) forIn(f forIn) value {
	var items []value
	// Over a module array (one name per item) or dictionary (key, value).
	if f.iter != nil {
		v := e.eval(f.iter)
		var keys []value
		switch c := v.o.(type) {
		case arr:
			for _, x := range c[:min(len(c), maxLoop)] {
				items = append(items, toValue(x))
			}
		case dict:
			names := make([]string, 0, len(c))
			for k := range c {
				names = append(names, k)
			}
			slices.Sort(names)
			for _, k := range names[:min(len(names), maxLoop)] {
				keys = append(keys, value{kind: 's', s: k})
				items = append(items, toValue(c[k]))
			}
		default:
			return undefined
		}
		held := 0
		for i, v := range items {
			if keys != nil {
				e.vars = append(e.vars, binding{f.names[0], keys[i]}, binding{f.names[1], v})
			} else {
				e.vars = append(e.vars, binding{f.names[0], v})
			}
			if e.eval(f.body).truth() {
				held++
			}
			e.vars = e.vars[:len(e.vars)-len(f.names)]
		}
		return e.quantified(f.quant, f.all, f.none, false, held, len(items))
	}
	if f.list != nil {
		for _, x := range f.list {
			items = append(items, e.eval(x))
		}
	} else {
		lo, hi := e.eval(f.lo), e.eval(f.hi)
		if lo.kind != 'i' || hi.kind != 'i' {
			return undefined
		}
		if hi.i-lo.i >= maxLoop {
			hi.i = lo.i + maxLoop - 1
		}
		for i := lo.i; i <= hi.i; i++ {
			items = append(items, intV(i))
		}
	}
	held := 0
	for _, v := range items {
		e.vars = append(e.vars, binding{f.names[0], v})
		if e.eval(f.body).truth() {
			held++
		}
		e.vars = e.vars[:len(e.vars)-1]
	}
	return e.quantified(f.quant, f.all, f.none, false, held, len(items))
}

// excerpt is up to 32 bytes of a match's data.
func (e *evaluator) excerpt(h hit) []byte {
	for _, b := range e.blocks {
		if h.off >= b.Base && h.off-b.Base < uint64(len(b.Data)) {
			start := h.off - b.Base
			return append([]byte(nil), b.Data[start:min(start+uint64(min(h.n, 32)), uint64(len(b.Data)))]...)
		}
	}
	return nil
}
