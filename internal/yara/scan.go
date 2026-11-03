package yara

import (
	"context"
	"errors"
	"slices"
)

// Limits on what one scan collects.
const (
	// MaxMatchesPerString caps the matches kept per string and block; a
	// count condition sees at most this many.
	MaxMatchesPerString = 10_000
	// MaxSource bounds a rule set's source.
	MaxSource = 4 << 20
	// hexBudget bounds the steps of one hex string check (jumps and
	// alternatives backtrack).
	hexBudget = 100_000
)

// Rules is a compiled rule set, safe for concurrent scans.
type Rules struct {
	rules    []*Rule
	patterns []*pattern
	ac       *automaton
	// fullScan are regular expressions without a literal prefix and hex
	// strings without an atom, run over the whole data.
	fullScan []*pattern
	// uses names the modules the rules use.
	uses map[string]bool
}

// Uses reports whether the rules use a module (imported, or pe through
// the entrypoint keyword).
func (r *Rules) Uses(module string) bool { return r.uses[module] }

// Compile parses and compiles rules.
func Compile(src string) (*Rules, error) {
	if len(src) > MaxSource {
		return nil, errors.New("the rules are larger than 4 MiB")
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, rules: map[string]*Rule{}}
	if err := p.parse(); err != nil {
		return nil, err
	}
	if len(p.order) == 0 {
		return nil, errors.New("no rules")
	}
	rs := &Rules{rules: p.order, uses: map[string]bool{}}
	for name := range p.imports {
		rs.uses[name] = true
	}
	if p.entrypoint {
		rs.uses["pe"] = true
	}
	var lits []acLit
	for _, r := range p.order {
		for _, s := range r.strings {
			idx := len(rs.patterns)
			rs.patterns = append(rs.patterns, s)
			switch {
			case s.lits != nil:
				for i, l := range s.lits {
					lits = append(lits, acLit{bytes: l, pattern: idx, variant: i})
				}
			case s.hex != nil && s.atom != nil:
				lits = append(lits, acLit{bytes: s.atom, pattern: idx, variant: -1})
			case s.re != nil && s.rePrefix != nil:
				lits = append(lits, acLit{bytes: s.rePrefix, pattern: idx, variant: -1})
			default:
				rs.fullScan = append(rs.fullScan, s)
			}
		}
	}
	rs.ac = buildAutomaton(lits)
	return rs, nil
}

// Len is the number of rules.
func (r *Rules) Len() int { return len(r.rules) }

// Block is scanned data at a base address: a file (base 0) or a region of
// a process's memory.
type Block struct {
	Base uint64
	Data []byte
}

// Match is a rule that matched.
type Match struct {
	Rule    string        `json:"rule"`
	Tags    []string      `json:"tags,omitempty"`
	Meta    []Meta        `json:"meta,omitempty"`
	Strings []StringMatch `json:"strings,omitempty"`
}

// StringMatch is one match of a string, with up to 32 bytes of its data.
type StringMatch struct {
	ID     string `json:"id"`
	Offset uint64 `json:"offset"`
	Length int    `json:"length"`
	Data   []byte `json:"data"`
}

type hit struct {
	off uint64
	n   int
}

// Target is what modules describe besides the scanned blocks: Image is a
// process's main executable as mapped in memory, for a memory scan (nil
// when scanning a file, whose blocks are the file).
type Target struct {
	Image *Block
}

// Scan runs the rules over blocks. size is the file size for filesize, or
// -1 when scanning memory (filesize is then undefined). The context stops
// a long scan.
func (r *Rules) Scan(ctx context.Context, blocks []Block, size int64) ([]Match, error) {
	return r.ScanTarget(ctx, blocks, size, Target{})
}

// ScanTarget is Scan with what the modules describe.
func (r *Rules) ScanTarget(ctx context.Context, blocks []Block, size int64, target Target) ([]Match, error) {
	hits := make([][]hit, len(r.patterns))
	add := func(pi int, off uint64, n int) bool {
		if len(hits[pi]) >= MaxMatchesPerString {
			return false
		}
		hits[pi] = append(hits[pi], hit{off, n})
		return true
	}
	for _, b := range blocks {
		if err := r.scanBlock(ctx, b, add); err != nil {
			return nil, err
		}
	}
	for i := range hits {
		slices.SortFunc(hits[i], func(a, b hit) int {
			switch {
			case a.off < b.off:
				return -1
			case a.off > b.off:
				return 1
			}
			return 0
		})
		hits[i] = slices.CompactFunc(hits[i], func(a, b hit) bool { return a.off == b.off })
	}
	e := &evaluator{rs: r, hits: hits, blocks: blocks, size: size, results: map[*Rule]bool{}, index: map[*pattern]int{}, target: target}
	for i, p := range r.patterns {
		e.index[p] = i
	}
	for _, rule := range r.rules {
		if rule.Global && !e.rule(rule) {
			return nil, nil
		}
	}
	var out []Match
	for _, rule := range r.rules {
		if rule.Private || !e.rule(rule) {
			continue
		}
		m := Match{Rule: rule.Name, Tags: rule.Tags, Meta: rule.Meta}
		for _, s := range rule.strings {
			if s.private {
				continue
			}
			for _, h := range hits[e.index[s]] {
				if len(m.Strings) >= 100 {
					break
				}
				m.Strings = append(m.Strings, StringMatch{ID: s.id, Offset: h.off, Length: h.n, Data: e.excerpt(h)})
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *Rules) scanBlock(ctx context.Context, b Block, add func(int, uint64, int) bool) error {
	data := b.Data
	err := r.ac.scan(ctx, data, func(end int, l acLit) {
		p := r.patterns[l.pattern]
		start := end - len(l.bytes) + 1
		switch {
		case p.lits != nil:
			lit := p.lits[l.variant]
			if !litAt(data, start, lit, p.nocase) || p.fullword && !wordBounded(data, start, len(lit), p.wide[l.variant]) {
				return
			}
			add(l.pattern, b.Base+uint64(start), len(lit))
		case p.hex != nil:
			at := start - p.atomAt
			budget := hexBudget
			if at < 0 {
				return
			}
			if n := matchHex(p.hex, data, at, &budget); n >= 0 {
				add(l.pattern, b.Base+uint64(at), n)
			}
		case p.re != nil:
			if n := p.regexAt(data, start); n >= 0 && (!p.fullword || wordBounded(data, start, n, false)) {
				add(l.pattern, b.Base+uint64(start), n)
			}
		}
	})
	if err != nil {
		return err
	}
	for _, p := range r.fullScan {
		pi := slices.Index(r.patterns, p)
		if p.re != nil {
			p.regexAll(data, func(off, n int) bool {
				if p.fullword && !wordBounded(data, off, n, false) {
					return true
				}
				return add(pi, b.Base+uint64(off), n)
			})
			continue
		}
		for off := range data {
			if off%(1<<20) == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			budget := hexBudget
			if n := matchHex(p.hex, data, off, &budget); n >= 0 && !add(pi, b.Base+uint64(off), n) {
				break
			}
		}
	}
	return ctx.Err()
}

// automaton is an Aho-Corasick automaton over byte strings, matched
// case-insensitively (ASCII); callers check case where it matters.
type automaton struct {
	next []map[byte]int32
	fail []int32
	out  [][]acLit
	// delta is the full transition table (failure links folded in, case
	// folded) when the automaton is small enough: one lookup per byte.
	delta [][256]int32
	// hasOut marks states with matches.
	hasOut []bool
}

// maxDense bounds the states given a full transition table (1 KiB each).
const maxDense = 1 << 16

type acLit struct {
	bytes   []byte
	pattern int
	variant int
}

func buildAutomaton(lits []acLit) *automaton {
	a := &automaton{next: []map[byte]int32{{}}, fail: []int32{0}, out: [][]acLit{nil}}
	for _, l := range lits {
		s := int32(0)
		for _, c := range l.bytes {
			c = lower(c)
			n, ok := a.next[s][c]
			if !ok {
				n = int32(len(a.next))
				a.next = append(a.next, map[byte]int32{})
				a.fail = append(a.fail, 0)
				a.out = append(a.out, nil)
				a.next[s][c] = n
			}
			s = n
		}
		a.out[s] = append(a.out[s], l)
	}
	// Breadth-first failure links.
	queue := []int32{}
	for _, n := range a.next[0] {
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for c, n := range a.next[s] {
			queue = append(queue, n)
			f := a.fail[s]
			for {
				if m, ok := a.next[f][c]; ok && m != n {
					a.fail[n] = m
					break
				}
				if f == 0 {
					a.fail[n] = 0
					break
				}
				f = a.fail[f]
			}
			a.out[n] = append(a.out[n], a.out[a.fail[n]]...)
		}
	}
	if len(a.next) <= maxDense {
		a.dense()
	}
	return a
}

// dense computes the full transition table in breadth-first order: a
// state's missing transitions are its failure state's. Upper-case letters
// go where their lower-case forms go.
func (a *automaton) dense() {
	a.delta = make([][256]int32, len(a.next))
	a.hasOut = make([]bool, len(a.next))
	queue := []int32{0}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		a.hasOut[s] = len(a.out[s]) > 0
		for c := range 256 {
			lc := lower(byte(c))
			if n, ok := a.next[s][lc]; ok {
				a.delta[s][c] = n
				if byte(c) == lc {
					queue = append(queue, n)
				}
			} else if s != 0 {
				a.delta[s][c] = a.delta[a.fail[s]][c]
			}
		}
	}
}

func (a *automaton) scanDense(ctx context.Context, data []byte, found func(end int, l acLit)) error {
	s := int32(0)
	delta, hasOut := a.delta, a.hasOut
	for start := 0; start < len(data); start += 1 << 20 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		end := min(start+1<<20, len(data))
		for i := start; i < end; i++ {
			s = delta[s][data[i]]
			if hasOut[s] {
				for _, l := range a.out[s] {
					found(i, l)
				}
			}
		}
	}
	return nil
}

func (a *automaton) scan(ctx context.Context, data []byte, found func(end int, l acLit)) error {
	if a.delta != nil {
		return a.scanDense(ctx, data, found)
	}
	s := int32(0)
	for i, c := range data {
		if i%(1<<20) == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		c = lower(c)
		for {
			if n, ok := a.next[s][c]; ok {
				s = n
				break
			}
			if s == 0 {
				break
			}
			s = a.fail[s]
		}
		for _, l := range a.out[s] {
			found(i, l)
		}
	}
	return nil
}
