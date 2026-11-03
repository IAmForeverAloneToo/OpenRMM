package yara

import (
	"fmt"
	"slices"
	"strings"
)

// Rule is a compiled rule.
type Rule struct {
	Name    string
	Tags    []string
	Meta    []Meta
	Private bool
	Global  bool
	strings []*pattern
	cond    node
	line    int
}

// Meta is one meta value of a rule.
type Meta struct {
	Key   string
	Value any // string, int64 or bool
}

// node is a condition expression.
type node interface{}

type (
	boolLit   struct{ v bool }
	intLit    struct{ v int64 }
	strLit    struct{ v string }
	filesizeN struct{}
	unary     struct {
		op string
		x  node
	}
	binop struct {
		op   string
		x, y node
	}
	strMatch struct{ p *pattern } // $a
	strCount struct{ p *pattern } // #a
	strAt    struct {             // $a at x
		p *pattern
		x node
	}
	strIn struct { // $a in (x..y)
		p    *pattern
		x, y node
	}
	strOffset struct { // @a[i], !a[i]
		p      *pattern
		i      node
		length bool
	}
	intRead struct { // uint32(x), int16be(x)
		size   int
		signed bool
		big    bool
		x      node
	}
	ofExpr struct { // any of ($a*), 2 of them, 50% of them, any of (rule1, rule2)
		quant   node // nil: any; "all"; "none"; number
		all     bool
		none    bool
		percent bool
		set     []*pattern
		rules   []*Rule
		in      *rangeN // N of them in (x..y)
	}
	forOf struct { // for any of ($a*) : ( cond with $ )
		of   *ofExpr
		body node
	}
	forIn struct { // for any i in (1..#a) : ( cond with i ), for any s in pe.sections : (...)
		quant node
		all   bool
		none  bool
		names []string // one, or key and value for a dictionary
		lo    node
		hi    node
		list  []node
		iter  node // a module array or dictionary
		body  node
	}
	varRef  struct{ name string }
	ruleRef struct{ r *Rule }
	anonRef struct {
		kind string // "$", "#", "@", "!"
		i    node   // for @ and !
		at   node   // $ at x
		in   *rangeN
	}
	rangeN struct{ x, y node }
)

type parser struct {
	toks  []token
	pos   int
	rules map[string]*Rule
	order []*Rule
	// Inside a rule: its strings by identifier.
	cur  *Rule
	vars []varDef
	// anon is the string bound by a for-of loop body ($, #, @, !).
	inForOf int
	// imports are the modules the rules imported; entrypoint is set when a
	// condition uses the entrypoint keyword (the pe module).
	imports    map[string]*module
	entrypoint bool
	// fields are the module fields conditions reach directly ("pe.is_signed").
	fields map[string]bool
}

// varDef is a loop variable and its type.
type varDef struct {
	name string
	t    *ftype
}

func (p *parser) varType(name string) *ftype {
	for i := len(p.vars) - 1; i >= 0; i-- {
		if p.vars[i].name == name {
			return p.vars[i].t
		}
	}
	return nil
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) take() token {
	t := p.toks[p.pos]
	if t.kind != tEOF {
		p.pos++
	}
	return t
}

func (p *parser) errorf(t token, format string, args ...any) error {
	return &Error{Line: t.line, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) is(kind tokenKind, text string) bool {
	t := p.peek()
	return t.kind == kind && t.text == text
}

func (p *parser) expect(kind tokenKind, text string) (token, error) {
	t := p.take()
	if t.kind != kind || text != "" && t.text != text {
		want := text
		if want == "" {
			want = map[tokenKind]string{tIdent: "a name", tString: "a text string", tNumber: "a number"}[kind]
		}
		return t, p.errorf(t, "expected %s, found %s", want, t)
	}
	return t, nil
}

func (p *parser) parse() error {
	for p.peek().kind != tEOF {
		t := p.peek()
		switch {
		case t.kind == tKeyword && t.text == "import":
			p.take()
			name, err := p.expect(tString, "")
			if err != nil {
				return err
			}
			m := modules[name.text]
			if m == nil {
				return p.errorf(t, "module %q is not supported; supported modules: %s", name.text, supported())
			}
			if p.imports == nil {
				p.imports = map[string]*module{}
			}
			p.imports[m.name] = m
		case t.kind == tKeyword && t.text == "include":
			return p.errorf(t, "include is not supported; paste the included rules instead")
		default:
			if err := p.rule(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *parser) rule() error {
	r := &Rule{line: p.peek().line}
	for p.is(tKeyword, "private") || p.is(tKeyword, "global") {
		if p.take().text == "private" {
			r.Private = true
		} else {
			r.Global = true
		}
	}
	if _, err := p.expect(tKeyword, "rule"); err != nil {
		return err
	}
	name, err := p.expect(tIdent, "")
	if err != nil {
		return err
	}
	if strings.Contains(name.text, ".") {
		return p.errorf(name, "bad rule name %q", name.text)
	}
	if p.rules[name.text] != nil {
		return p.errorf(name, "duplicate rule %q", name.text)
	}
	r.Name = name.text
	if p.is(tPunct, ":") {
		p.take()
		for p.peek().kind == tIdent {
			r.Tags = append(r.Tags, p.take().text)
		}
	}
	if _, err := p.expect(tPunct, "{"); err != nil {
		return err
	}
	p.cur = r
	if p.is(tKeyword, "meta") {
		p.take()
		if _, err := p.expect(tPunct, ":"); err != nil {
			return err
		}
		for p.peek().kind == tIdent || p.peek().kind == tKeyword && !p.is(tKeyword, "strings") && !p.is(tKeyword, "condition") {
			key := p.take()
			if _, err := p.expect(tPunct, "="); err != nil {
				return err
			}
			v := p.take()
			neg := false
			if v.kind == tPunct && v.text == "-" {
				neg, v = true, p.take()
			}
			switch {
			case v.kind == tString:
				r.Meta = append(r.Meta, Meta{key.text, v.text})
			case v.kind == tNumber:
				n := v.num
				if neg {
					n = -n
				}
				r.Meta = append(r.Meta, Meta{key.text, n})
			case v.kind == tKeyword && (v.text == "true" || v.text == "false"):
				r.Meta = append(r.Meta, Meta{key.text, v.text == "true"})
			default:
				return p.errorf(v, "bad meta value %s", v)
			}
		}
	}
	if p.is(tKeyword, "strings") {
		p.take()
		if _, err := p.expect(tPunct, ":"); err != nil {
			return err
		}
		for p.peek().kind == tStrID {
			if err := p.stringDef(r); err != nil {
				return err
			}
		}
	}
	if _, err := p.expect(tKeyword, "condition"); err != nil {
		return err
	}
	if _, err := p.expect(tPunct, ":"); err != nil {
		return err
	}
	r.cond, err = p.expr()
	if err != nil {
		return err
	}
	if _, err := p.expect(tPunct, "}"); err != nil {
		return err
	}
	for _, s := range r.strings {
		if !s.used && !s.private {
			return p.errorf(token{line: r.line}, "string %s in rule %s is never used", s.id, r.Name)
		}
	}
	p.rules[r.Name] = r
	p.order = append(p.order, r)
	p.cur = nil
	return nil
}

func (p *parser) stringDef(r *Rule) error {
	id := p.take()
	if strings.HasSuffix(id.text, "*") {
		return p.errorf(id, "bad string name %s", id.text)
	}
	if id.text != "$" {
		for _, s := range r.strings {
			if s.id == id.text {
				return p.errorf(id, "duplicate string %s", id.text)
			}
		}
	}
	if _, err := p.expect(tPunct, "="); err != nil {
		return err
	}
	v := p.take()
	s := &pattern{id: id.text, line: id.line}
	var mods []string
	for p.peek().kind == tKeyword {
		m := p.peek().text
		if m != "ascii" && m != "wide" && m != "nocase" && m != "fullword" && m != "private" && m != "xor" && m != "base64" && m != "base64wide" {
			break
		}
		p.take()
		if m == "xor" || m == "base64" || m == "base64wide" {
			return p.errorf(id, "the %s modifier is not supported", m)
		}
		mods = append(mods, m)
	}
	var err error
	switch v.kind {
	case tString:
		err = s.compileText(v.text, mods)
	case tHex:
		err = s.compileHex(v.text, mods)
	case tRegex:
		err = s.compileRegex(v.text, v.flags, mods)
	default:
		return p.errorf(v, "expected a text, hex or regular expression string, found %s", v)
	}
	if err != nil {
		return p.errorf(id, "%s: %v", id.text, err)
	}
	r.strings = append(r.strings, s)
	return nil
}

// supported lists the modules that can be imported.
func supported() string {
	var names []string
	for n := range modules {
		names = append(names, n)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// Expression grammar, lowest precedence first: or, and, not, comparison,
// bitwise or, xor, and, shift, additive, multiplicative, unary, primary.

func (p *parser) expr() (node, error) { return p.or() }

func (p *parser) or() (node, error) {
	x, err := p.and()
	for err == nil && p.is(tKeyword, "or") {
		p.take()
		var y node
		if y, err = p.and(); err == nil {
			x = binop{"or", x, y}
		}
	}
	return x, err
}

func (p *parser) and() (node, error) {
	x, err := p.not()
	for err == nil && p.is(tKeyword, "and") {
		p.take()
		var y node
		if y, err = p.not(); err == nil {
			x = binop{"and", x, y}
		}
	}
	return x, err
}

func (p *parser) not() (node, error) {
	if p.is(tKeyword, "not") {
		p.take()
		x, err := p.not()
		return unary{"not", x}, err
	}
	if p.is(tKeyword, "defined") {
		p.take()
		x, err := p.not()
		return unary{"defined", x}, err
	}
	return p.compare()
}

var comparisons = []string{"==", "!=", "<=", ">=", "<", ">"}

func (p *parser) compare() (node, error) {
	x, err := p.bitOr()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	switch {
	case t.kind == tPunct && containsStr(comparisons, t.text):
		p.take()
		y, err := p.bitOr()
		return binop{t.text, x, y}, err
	case t.kind == tKeyword && containsStr([]string{"contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "iequals"}, t.text):
		p.take()
		y, err := p.bitOr()
		return binop{t.text, x, y}, err
	case t.kind == tKeyword && t.text == "matches":
		p.take()
		re := p.take()
		if re.kind != tRegex {
			return nil, p.errorf(re, "expected a regular expression after matches")
		}
		pt := &pattern{}
		if err := pt.compileRegex(re.text, re.flags, nil); err != nil {
			return nil, p.errorf(re, "%v", err)
		}
		return binop{"matches", x, pt}, nil
	}
	return x, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (p *parser) binaryLevel(ops []string, next func() (node, error)) (node, error) {
	x, err := next()
	for err == nil && p.peek().kind == tPunct && containsStr(ops, p.peek().text) {
		op := p.take().text
		var y node
		if y, err = next(); err == nil {
			x = binop{op, x, y}
		}
	}
	return x, err
}

func (p *parser) bitOr() (node, error)  { return p.binaryLevel([]string{"|"}, p.bitXor) }
func (p *parser) bitXor() (node, error) { return p.binaryLevel([]string{"^"}, p.bitAnd) }
func (p *parser) bitAnd() (node, error) { return p.binaryLevel([]string{"&"}, p.shift) }
func (p *parser) shift() (node, error)  { return p.binaryLevel([]string{"<<", ">>"}, p.add) }
func (p *parser) add() (node, error)    { return p.binaryLevel([]string{"+", "-"}, p.mul) }
func (p *parser) mul() (node, error)    { return p.binaryLevel([]string{"*", "\\", "%"}, p.unaryOp) }

func (p *parser) unaryOp() (node, error) {
	if p.is(tPunct, "-") || p.is(tPunct, "~") {
		op := p.take().text
		x, err := p.unaryOp()
		return unary{op, x}, err
	}
	return p.primary()
}

// intFuncs are the integer reads: name to size, signed, big-endian.
var intFuncs = map[string]struct {
	size        int
	signed, big bool
}{
	"uint8": {1, false, false}, "uint16": {2, false, false}, "uint32": {4, false, false},
	"int8": {1, true, false}, "int16": {2, true, false}, "int32": {4, true, false},
	"uint8be": {1, false, true}, "uint16be": {2, false, true}, "uint32be": {4, false, true},
	"int8be": {1, true, true}, "int16be": {2, true, true}, "int32be": {4, true, true},
}

func (p *parser) primary() (node, error) {
	t := p.peek()
	switch t.kind {
	case tNumber:
		// A number of strings or rules: "2 of them", "50% of ($a*)".
		if n := p.toks[p.pos+1]; n.kind == tKeyword && n.text == "of" || n.kind == tPunct && n.text == "%" && p.toks[p.pos+2].kind == tKeyword && p.toks[p.pos+2].text == "of" {
			return p.of()
		}
		p.take()
		return intLit{t.num}, nil
	case tFloat:
		p.take()
		return floatLit{t.f}, nil
	case tString:
		p.take()
		return strLit{t.text}, nil
	case tPunct:
		if t.text == "(" {
			p.take()
			x, err := p.expr()
			if err != nil {
				return nil, err
			}
			_, err = p.expect(tPunct, ")")
			return x, err
		}
	case tKeyword:
		switch t.text {
		case "true", "false":
			p.take()
			return boolLit{t.text == "true"}, nil
		case "filesize":
			p.take()
			return filesizeN{}, nil
		case "entrypoint":
			// The older form of pe.entry_point; it needs no import.
			p.take()
			p.entrypoint = true
			return entryN{}, nil
		case "any", "all", "none":
			return p.of()
		case "for":
			return p.forExpr()
		case "them":
			return nil, p.errorf(t, "them must follow of")
		}
	case tStrID:
		return p.stringExpr()
	case tCount, tOffset, tLength:
		return p.matchInfo()
	case tIdent:
		p.take()
		if f, ok := intFuncs[t.text]; ok {
			if _, err := p.expect(tPunct, "("); err != nil {
				return nil, err
			}
			x, err := p.expr()
			if err != nil {
				return nil, err
			}
			_, err = p.expect(tPunct, ")")
			return intRead{f.size, f.signed, f.big, x}, err
		}
		if p.varType(t.text) != nil || p.imports[t.text] != nil {
			n, ft, err := p.reference(t)
			if err == nil && (ft.kind == 'S' || ft.kind == 'A' || ft.kind == 'D') {
				err = p.errorf(t, "%s is not a value; use one of its fields, or loop over it with for", t.text)
			}
			return n, err
		}
		if r := p.rules[t.text]; r != nil {
			return ruleRef{r}, nil
		}
		if p.is(tPunct, ".") {
			if modules[t.text] != nil {
				return nil, p.errorf(t, "%s is used without import %q", t.text, t.text)
			}
			if containsStr(knownModules, t.text) {
				return nil, p.errorf(t, "module %q is not supported; supported modules: %s", t.text, supported())
			}
		}
		// "2 of them" starts with a number; a name here is a loop
		// variable or rule, else unknown.
		return nil, p.errorf(t, "unknown identifier %q", t.text)
	}
	// A number of: "2 of ($a, $b)" or "50% of them".
	return nil, p.errorf(t, "unexpected %s", t)
}

// reference is a loop variable or an imported module (the name t, already
// taken) with its fields, indexes and calls.
func (p *parser) reference(t token) (node, *ftype, error) {
	if vt := p.varType(t.text); vt != nil {
		return p.postfix(varRef{t.text}, vt, t.text)
	}
	m := p.imports[t.text]
	if m == nil {
		return nil, nil, p.errorf(t, "unknown identifier %q", t.text)
	}
	if !p.is(tPunct, ".") {
		return nil, nil, p.errorf(t, "%s is a module; use one of its fields, such as %s.%s", t.text, t.text, firstField(m.t))
	}
	return p.postfix(modRef{m}, m.t, t.text)
}

// postfix reads ".field", "[index]" and "(arguments)" after a module or a
// loop variable holding module data, checking each against the types; path
// names the expression so far for errors.
func (p *parser) postfix(x node, t *ftype, path string) (node, *ftype, error) {
	for {
		switch {
		case p.is(tPunct, "."):
			p.take()
			name, err := p.expect(tIdent, "")
			if err != nil {
				return nil, nil, err
			}
			if t.kind != 'S' {
				return nil, nil, p.errorf(name, "%s has no field %s", path, name.text)
			}
			ft := t.fields[name.text]
			if ft == nil {
				return nil, nil, p.errorf(name, "%s has no field %s", path, name.text)
			}
			if m, ok := x.(modRef); ok {
				if p.fields == nil {
					p.fields = map[string]bool{}
				}
				p.fields[m.m.name+"."+name.text] = true
			}
			path += "." + name.text
			if ft.kind == 'F' {
				if _, err := p.expect(tPunct, "("); err != nil {
					return nil, nil, p.errorf(name, "%s is a function: call it as %s", path, signatures(path, ft))
				}
				var args []node
				for !p.is(tPunct, ")") {
					if len(args) > 0 {
						if _, err := p.expect(tPunct, ","); err != nil {
							return nil, nil, err
						}
					}
					a, err := p.argument()
					if err != nil {
						return nil, nil, err
					}
					args = append(args, a)
				}
				p.take()
				f := pick(ft, args, p.vars)
				if f == nil {
					return nil, nil, p.errorf(name, "wrong arguments for %s; use %s", path, signatures(path, ft))
				}
				x, t = callN{x: x, f: f, args: args, t: f.ret}, f.ret
				continue
			}
			x, t = fieldN{x: x, name: name.text, t: ft}, ft
		case p.is(tPunct, "["):
			open := p.take()
			if t.kind != 'A' && t.kind != 'D' {
				return nil, nil, p.errorf(open, "%s is not an array or dictionary", path)
			}
			i, err := p.expr()
			if err != nil {
				return nil, nil, err
			}
			if _, err := p.expect(tPunct, "]"); err != nil {
				return nil, nil, err
			}
			want := byte('i')
			if t.kind == 'D' {
				want = 's'
			}
			if !accepts(want, staticType(i, p.vars)) {
				return nil, nil, p.errorf(open, "%s needs an %s index", path, map[byte]string{'i': "integer", 's': "text"}[want])
			}
			x, t = indexN{x: x, i: i, t: t.elem}, t.elem
			path += "[]"
		default:
			return x, t, nil
		}
	}
}

// argument is a function argument: a regular expression or an expression.
func (p *parser) argument() (node, error) {
	if t := p.peek(); t.kind == tRegex {
		p.take()
		pt := &pattern{}
		if err := pt.compileRegex(t.text, t.flags, nil); err != nil {
			return nil, p.errorf(t, "%v", err)
		}
		return regexLit{pt}, nil
	}
	return p.expr()
}

// firstField names one field of a module, for an error message.
func firstField(t *ftype) string {
	var names []string
	for n, f := range t.fields {
		if f.kind != 'F' {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return "..."
	}
	return names[0]
}

// stringExpr is $a, $a at x or $a in (x..y), or $ inside a for-of body.
func (p *parser) stringExpr() (node, error) {
	t := p.take()
	if t.text == "$" && p.inForOf > 0 {
		a := anonRef{kind: "$"}
		switch {
		case p.is(tKeyword, "at"):
			p.take()
			x, err := p.add()
			if err != nil {
				return nil, err
			}
			a.at = x
		case p.is(tKeyword, "in"):
			p.take()
			r, err := p.rangeExpr()
			if err != nil {
				return nil, err
			}
			a.in = &r
		}
		return a, nil
	}
	s, err := p.lookup(t)
	if err != nil {
		return nil, err
	}
	if p.is(tKeyword, "at") {
		p.take()
		x, err := p.add()
		return strAt{s, x}, err
	}
	if p.is(tKeyword, "in") {
		p.take()
		r, err := p.rangeExpr()
		if err != nil {
			return nil, err
		}
		return strIn{s, r.x, r.y}, nil
	}
	return strMatch{s}, nil
}

func (p *parser) lookup(t token) (*pattern, error) {
	if p.cur == nil {
		return nil, p.errorf(t, "%s outside a rule", t.text)
	}
	id := "$" + t.text[1:]
	for _, s := range p.cur.strings {
		if s.id == id {
			s.used = true
			return s, nil
		}
	}
	return nil, p.errorf(t, "undefined string %s", id)
}

// matchInfo is #a, @a[i] or !a[i] (or #, @[i], ![i] in a for-of body).
func (p *parser) matchInfo() (node, error) {
	t := p.take()
	anon := len(t.text) == 1
	if anon && p.inForOf == 0 {
		return nil, p.errorf(t, "%s outside a for-of loop", t.text)
	}
	var s *pattern
	if !anon {
		var err error
		if s, err = p.lookup(t); err != nil {
			return nil, err
		}
	}
	if t.kind == tCount {
		if anon {
			return anonRef{kind: "#"}, nil
		}
		if p.is(tKeyword, "in") {
			p.take()
			r, err := p.rangeExpr()
			if err != nil {
				return nil, err
			}
			// #a in (x..y): the number of matches in the range.
			return binop{"countin", strCount{s}, r}, nil
		}
		return strCount{s}, nil
	}
	var i node = intLit{1}
	if p.is(tPunct, "[") {
		p.take()
		var err error
		if i, err = p.expr(); err != nil {
			return nil, err
		}
		if _, err := p.expect(tPunct, "]"); err != nil {
			return nil, err
		}
	}
	if anon {
		return anonRef{kind: t.text[:1], i: i}, nil
	}
	return strOffset{s, i, t.kind == tLength}, nil
}

func (p *parser) rangeExpr() (rangeN, error) {
	if _, err := p.expect(tPunct, "("); err != nil {
		return rangeN{}, err
	}
	x, err := p.add()
	if err != nil {
		return rangeN{}, err
	}
	if _, err := p.expect(tPunct, ".."); err != nil {
		return rangeN{}, err
	}
	y, err := p.add()
	if err != nil {
		return rangeN{}, err
	}
	_, err = p.expect(tPunct, ")")
	return rangeN{x, y}, err
}

// of parses "<quantifier> of <set> [in (x..y)]".
func (p *parser) of() (node, error) {
	o, err := p.quantifier()
	if err != nil {
		return nil, err
	}
	if _, err := p.expect(tKeyword, "of"); err != nil {
		return nil, err
	}
	if err := p.set(o); err != nil {
		return nil, err
	}
	if p.is(tKeyword, "in") && o.rules == nil {
		p.take()
		r, err := p.rangeExpr()
		if err != nil {
			return nil, err
		}
		o.in = &r
	}
	return o, nil
}

func (p *parser) quantifier() (*ofExpr, error) {
	o := &ofExpr{}
	t := p.peek()
	switch {
	case t.kind == tKeyword && t.text == "any":
		p.take()
	case t.kind == tKeyword && t.text == "all":
		p.take()
		o.all = true
	case t.kind == tKeyword && t.text == "none":
		p.take()
		o.none = true
	default:
		// A number is taken as it is: primary would read "2 of" as an
		// of expression again.
		var x node = intLit{p.peek().num}
		if p.peek().kind == tNumber {
			p.take()
		} else {
			var err error
			if x, err = p.unaryOp(); err != nil {
				return nil, err
			}
		}
		if p.is(tPunct, "%") {
			p.take()
			o.percent = true
		}
		o.quant = x
	}
	return o, nil
}

// set is "them", "($a, $b*)" or "(rule1, rule2*)".
func (p *parser) set(o *ofExpr) error {
	if p.is(tKeyword, "them") {
		p.take()
		if p.cur == nil || len(p.cur.strings) == 0 {
			return p.errorf(p.peek(), "them used in a rule without strings")
		}
		for _, s := range p.cur.strings {
			s.used = true
		}
		o.set = p.cur.strings
		return nil
	}
	if _, err := p.expect(tPunct, "("); err != nil {
		return err
	}
	for {
		t := p.take()
		switch t.kind {
		case tStrID:
			if strings.HasSuffix(t.text, "*") {
				prefix := t.text[:len(t.text)-1]
				n := 0
				for _, s := range p.cur.strings {
					if strings.HasPrefix(s.id, prefix) {
						s.used = true
						o.set = append(o.set, s)
						n++
					}
				}
				if n == 0 {
					return p.errorf(t, "no strings match %s", t.text)
				}
			} else {
				s, err := p.lookup(t)
				if err != nil {
					return err
				}
				o.set = append(o.set, s)
			}
		case tIdent:
			if strings.HasSuffix(t.text, "*") {
				return p.errorf(t, "rule wildcards are not supported")
			}
			r := p.rules[t.text]
			if r == nil {
				return p.errorf(t, "unknown rule %q", t.text)
			}
			o.rules = append(o.rules, r)
		default:
			return p.errorf(t, "expected a string or rule, found %s", t)
		}
		if p.is(tPunct, ",") {
			p.take()
			continue
		}
		_, err := p.expect(tPunct, ")")
		if o.set != nil && o.rules != nil {
			return p.errorf(t, "a set cannot mix strings and rules")
		}
		return err
	}
}

// forExpr is "for <quantifier> of <set> : ( body )" or
// "for <quantifier> <name> in (<range or list>) : ( body )".
func (p *parser) forExpr() (node, error) {
	p.take()
	o, err := p.quantifier()
	if err != nil {
		return nil, err
	}
	if p.is(tKeyword, "of") {
		p.take()
		if err := p.set(o); err != nil {
			return nil, err
		}
		if o.rules != nil {
			return nil, p.errorf(p.peek(), "for ... of needs strings")
		}
		if _, err := p.expect(tPunct, ":"); err != nil {
			return nil, err
		}
		if _, err := p.expect(tPunct, "("); err != nil {
			return nil, err
		}
		p.inForOf++
		body, err := p.expr()
		p.inForOf--
		if err != nil {
			return nil, err
		}
		_, err = p.expect(tPunct, ")")
		return forOf{o, body}, err
	}
	name, err := p.expect(tIdent, "")
	if err != nil {
		return nil, err
	}
	f := forIn{quant: o.quant, all: o.all, none: o.none, names: []string{name.text}}
	for p.is(tPunct, ",") {
		p.take()
		n, err := p.expect(tIdent, "")
		if err != nil {
			return nil, err
		}
		f.names = append(f.names, n.text)
	}
	if _, err := p.expect(tKeyword, "in"); err != nil {
		return nil, err
	}
	if o.percent {
		return nil, p.errorf(name, "percentages are not supported in for ... in")
	}
	if !p.is(tPunct, "(") {
		// A module array (one name) or dictionary (key and value names).
		t := p.take()
		if t.kind != tIdent {
			return nil, p.errorf(t, "expected a range, a list or a module array, found %s", t)
		}
		it, ft, err := p.reference(t)
		if err != nil {
			return nil, err
		}
		var defs []varDef
		switch {
		case ft.kind == 'A' && len(f.names) == 1:
			defs = []varDef{{f.names[0], ft.elem}}
		case ft.kind == 'D' && len(f.names) == 2:
			defs = []varDef{{f.names[0], tStr}, {f.names[1], ft.elem}}
		case ft.kind == 'A' || ft.kind == 'D':
			return nil, p.errorf(name, "loop over an array with one name, over a dictionary with two (key, value)")
		default:
			return nil, p.errorf(t, "%s is not an array or dictionary", t.text)
		}
		f.iter = it
		return p.forBody(f, defs)
	}
	if len(f.names) != 1 {
		return nil, p.errorf(name, "a range or list takes one loop name")
	}
	if _, err := p.expect(tPunct, "("); err != nil {
		return nil, err
	}
	first, err := p.add()
	if err != nil {
		return nil, err
	}
	if p.is(tPunct, "..") {
		p.take()
		if f.hi, err = p.add(); err != nil {
			return nil, err
		}
		f.lo = first
	} else {
		f.list = []node{first}
		for p.is(tPunct, ",") {
			p.take()
			x, err := p.add()
			if err != nil {
				return nil, err
			}
			f.list = append(f.list, x)
		}
	}
	if _, err := p.expect(tPunct, ")"); err != nil {
		return nil, err
	}
	vt := tInt
	if f.list != nil {
		vt = staticType(f.list[0], p.vars)
	}
	return p.forBody(f, []varDef{{f.names[0], vt}})
}

// forBody reads ": ( body )" with the loop's names defined.
func (p *parser) forBody(f forIn, defs []varDef) (node, error) {
	if _, err := p.expect(tPunct, ":"); err != nil {
		return nil, err
	}
	if _, err := p.expect(tPunct, "("); err != nil {
		return nil, err
	}
	p.vars = append(p.vars, defs...)
	body, err := p.expr()
	p.vars = p.vars[:len(p.vars)-len(defs)]
	if err != nil {
		return nil, err
	}
	f.body = body
	_, err = p.expect(tPunct, ")")
	return f, err
}
