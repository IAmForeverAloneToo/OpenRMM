package yara

import (
	"sort"
	"strings"
)

// Modules. A module is a typed tree of fields that rules reach with
// "import" and dotted names: integers, decimals and text, structures,
// arrays, dictionaries and functions. The parser checks every name and
// function call against the module's types; at scan time the module builds
// its data once per scan, lazily, from what is scanned (Target).

// ftype is the type of a module field.
type ftype struct {
	kind   byte // 'i' integer, 'f' decimal, 's' text, 'S' structure, 'A' array, 'D' dictionary, 'F' function
	fields map[string]*ftype
	elem   *ftype
	funcs  []*fn
}

// fn is one overload of a module function. args lists the argument types
// ('i' integer, 'f' decimal, 's' text, 'r' regular expression, 'b' boolean);
// an integer is accepted where a decimal is expected.
type fn struct {
	args string
	ret  *ftype
	impl func(e *evaluator, self any, args []value) value
}

var (
	tInt   = &ftype{kind: 'i'}
	tFlt   = &ftype{kind: 'f'}
	tStr   = &ftype{kind: 's'}
	tBool  = &ftype{kind: 'i'} // module booleans are integers, as in YARA
	tUnset = &ftype{kind: '?'} // a value whose type is only known at scan time
)

func structT(fields map[string]*ftype) *ftype { return &ftype{kind: 'S', fields: fields} }
func arrayT(elem *ftype) *ftype               { return &ftype{kind: 'A', elem: elem} }
func dictT(elem *ftype) *ftype                { return &ftype{kind: 'D', elem: elem} }

// funcT is a function with its overloads.
func funcT(overloads ...*fn) *ftype { return &ftype{kind: 'F', funcs: overloads} }

func overload(args string, ret *ftype, impl func(e *evaluator, self any, args []value) value) *fn {
	return &fn{args: args, ret: ret, impl: impl}
}

// Module data at scan time: a structure is obj, an array arr, a dictionary
// dict; leaves are int64, float64 and string; nil is undefined.
type (
	obj  map[string]any
	arr  []any
	dict map[string]any
)

// module is an importable module. load builds its data for one scan (nil
// when the module does not apply, so every field is undefined); it runs at
// most once per scan and only if a condition reaches the module.
type module struct {
	name string
	t    *ftype
	load func(e *evaluator) any
}

var modules = map[string]*module{}

func register(m *module) { modules[m.name] = m }

// knownModules are YARA's modules, so that a rule naming one gets a clear
// refusal: not imported, or not supported (those not registered).
var knownModules = []string{"console", "cuckoo", "dex", "dotnet", "elf", "hash", "lnk", "macho", "magic", "math", "pe", "string", "time"}

// Nodes of module expressions.
type (
	modRef struct{ m *module }
	fieldN struct {
		x    node
		name string
		t    *ftype
	}
	indexN struct {
		x, i node
		t    *ftype
	}
	callN struct {
		x    node // the structure the function belongs to
		f    *fn
		args []node
		t    *ftype
	}
	regexLit struct{ p *pattern }
	floatLit struct{ v float64 }
	entryN   struct{} // entrypoint
)

// staticType is the type of an expression as far as the parser knows it:
// 'i', 'f', 's', 'b', 'r', a module type's kind, or '?'.
func staticType(n node, vars []varDef) *ftype {
	switch x := n.(type) {
	case intLit, filesizeN, strCount, strOffset, intRead, entryN:
		return tInt
	case floatLit:
		return tFlt
	case strLit:
		return tStr
	case regexLit:
		return &ftype{kind: 'r'}
	case fieldN:
		return x.t
	case indexN:
		return x.t
	case callN:
		return x.t
	case varRef:
		for i := len(vars) - 1; i >= 0; i-- {
			if vars[i].name == x.name {
				return vars[i].t
			}
		}
		return tUnset
	case unary:
		switch x.op {
		case "-":
			return staticType(x.x, vars)
		case "~":
			return tInt
		}
		return &ftype{kind: 'b'}
	case binop:
		switch x.op {
		case "+", "-", "*", "\\":
			if staticType(x.x, vars).kind == 'f' || staticType(x.y, vars).kind == 'f' {
				return tFlt
			}
			return tInt
		case "%", "&", "|", "^", "<<", ">>", "countin":
			return tInt
		}
	}
	return &ftype{kind: 'b'}
}

// accepts reports whether an argument of type have fits a parameter of
// type want.
func accepts(want byte, have *ftype) bool {
	switch {
	case have.kind == '?' || want == have.kind:
		return true
	case want == 'f':
		return have.kind == 'i'
	case want == 'b':
		return have.kind == 'i' || have.kind == 'b'
	case want == 'i':
		return have.kind == 'b'
	}
	return false
}

// pick chooses the overload of a function for the arguments.
func pick(f *ftype, args []node, vars []varDef) *fn {
	for _, o := range f.funcs {
		if len(o.args) != len(args) {
			continue
		}
		ok := true
		for i, a := range args {
			if !accepts(o.args[i], staticType(a, vars)) {
				ok = false
				break
			}
		}
		if ok {
			return o
		}
	}
	return nil
}

// signatures lists a function's overloads for an error message.
func signatures(name string, f *ftype) string {
	names := map[byte]string{'i': "integer", 'f': "number", 's': "text", 'r': "regex", 'b': "boolean"}
	var out []string
	for _, o := range f.funcs {
		var a []string
		for i := range len(o.args) {
			a = append(a, names[o.args[i]])
		}
		out = append(out, name+"("+strings.Join(a, ", ")+")")
	}
	sort.Strings(out)
	return strings.Join(out, " or ")
}

// toValue turns module data into a condition value.
func toValue(x any) value {
	switch v := x.(type) {
	case int64:
		return intV(v)
	case int:
		return intV(int64(v))
	case float64:
		return floatV(v)
	case string:
		return value{kind: 's', s: v}
	case bool:
		return boolV(v)
	case obj, arr, dict:
		return value{kind: 'o', o: v}
	}
	return undefined
}

// moduleData is a module's data for this scan, built on first use.
func (e *evaluator) moduleData(m *module) any {
	if v, ok := e.mods[m]; ok {
		return v
	}
	v := m.load(e)
	if e.mods == nil {
		e.mods = map[*module]any{}
	}
	e.mods[m] = v
	return v
}

func (e *evaluator) evalModule(n node) value {
	switch x := n.(type) {
	case entryN:
		if root, ok := e.moduleData(peModule).(obj); ok {
			return toValue(root["entry_point"])
		}
	case modRef:
		return toValue(e.moduleData(x.m))
	case fieldN:
		v := e.eval(x.x)
		if s, ok := v.o.(obj); ok {
			return toValue(s[x.name])
		}
	case indexN:
		v, i := e.eval(x.x), e.eval(x.i)
		switch c := v.o.(type) {
		case arr:
			if i.kind == 'i' && i.i >= 0 && i.i < int64(len(c)) {
				return toValue(c[i.i])
			}
		case dict:
			if i.kind == 's' {
				return toValue(c[i.s])
			}
		}
	case callN:
		self := e.eval(x.x)
		args := make([]value, len(x.args))
		for i, a := range x.args {
			if r, ok := a.(regexLit); ok {
				args[i] = value{kind: 'r', o: r.p}
				continue
			}
			args[i] = e.eval(a)
			// An integer passed for a decimal parameter.
			if x.f.args[i] == 'f' && args[i].kind == 'i' {
				args[i] = floatV(float64(args[i].i))
			}
		}
		return x.f.impl(e, self.o, args)
	}
	return undefined
}

// regexMatch tests a regular expression argument against text.
func regexMatch(r value, s string) bool {
	p, ok := r.o.(*pattern)
	return ok && p.re.FindReaderIndex(&byteReader{b: []byte(s)}) != nil
}

// rangeData is size bytes of the scanned data at offset, if one block
// holds them all.
func (e *evaluator) rangeData(offset, size value) ([]byte, bool) {
	if offset.kind != 'i' || size.kind != 'i' || offset.i < 0 || size.i < 0 {
		return nil, false
	}
	for _, b := range e.blocks {
		start := uint64(offset.i)
		if start >= b.Base && start-b.Base+uint64(size.i) <= uint64(len(b.Data)) {
			return b.Data[start-b.Base : start-b.Base+uint64(size.i)], true
		}
	}
	return nil, false
}
