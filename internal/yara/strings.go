package yara

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// pattern is a compiled string of a rule.
type pattern struct {
	id       string
	line     int
	used     bool
	private  bool
	nocase   bool
	fullword bool
	// Text strings: the byte sequences to find (ascii and/or wide forms);
	// wide marks which of them are wide, for fullword checks.
	lits [][]byte
	wide []bool
	// Hex strings.
	hex []hexToken
	// Regular expressions: the anchored form checks a candidate found by
	// its literal prefix; without a prefix of two or more bytes the
	// expression is run over the whole data.
	re       *regexp.Regexp
	reAnchor *regexp.Regexp
	rePrefix []byte
	// atom is a literal part of a hex string at a fixed distance (atomAt)
	// from its start, found first and then checked in full.
	atom   []byte
	atomAt int
}

// compileText compiles a text string with its modifiers.
func (p *pattern) compileText(s string, mods []string) error {
	if s == "" {
		return errors.New("empty string")
	}
	ascii, wide := false, false
	for _, m := range mods {
		switch m {
		case "ascii":
			ascii = true
		case "wide":
			wide = true
		case "nocase":
			p.nocase = true
		case "fullword":
			p.fullword = true
		case "private":
			p.private = true
		}
	}
	if !wide {
		ascii = true
	}
	if ascii {
		p.lits = append(p.lits, []byte(s))
		p.wide = append(p.wide, false)
	}
	if wide {
		w := make([]byte, 0, 2*len(s))
		for i := 0; i < len(s); i++ {
			w = append(w, s[i], 0)
		}
		p.lits = append(p.lits, w)
		p.wide = append(p.wide, true)
	}
	return nil
}

// hexToken is one element of a hex string: a byte with a mask, a jump of
// lo to hi bytes, or alternatives.
type hexToken struct {
	value, mask byte
	jump        bool
	lo, hi      int
	alts        [][]hexToken
}

// maxJump bounds an open jump ([n-]) and a hex string's search span.
const maxJump = 1 << 16

func (p *pattern) compileHex(body string, mods []string) error {
	for _, m := range mods {
		if m == "private" {
			p.private = true
		} else {
			return fmt.Errorf("hex strings take no %s modifier", m)
		}
	}
	src := strings.Join(strings.Fields(body), "")
	// Comments inside hex strings are not supported.
	toks, rest, err := hexSeq(src, 0)
	if err != nil {
		return err
	}
	if rest != "" {
		return fmt.Errorf("unexpected %q in hex string", rest[:1])
	}
	if len(toks) == 0 || toks[0].jump || toks[len(toks)-1].jump {
		return errors.New("a hex string cannot be empty or start or end with a jump")
	}
	p.hex = toks
	// The atom: the longest run of fully known bytes before the first
	// jump or alternative of variable length.
	at, run, best, bestAt := 0, []byte{}, []byte{}, 0
	for _, t := range toks {
		if t.jump || t.alts != nil {
			if t.alts != nil && fixedLen(t) >= 0 && !t.jump {
				// Alternatives of equal length keep later offsets fixed.
				if len(run) > len(best) {
					best, bestAt = run, at-len(run)
				}
				run = []byte{}
				at += fixedLen(t)
				continue
			}
			break
		}
		if t.mask == 0xFF {
			run = append(run, t.value)
		} else {
			if len(run) > len(best) {
				best, bestAt = run, at-len(run)
			}
			run = []byte{}
		}
		at++
	}
	if len(run) > len(best) {
		best, bestAt = run, at-len(run)
	}
	if len(best) >= 2 {
		p.atom, p.atomAt = best, bestAt
	}
	return nil
}

// fixedLen is a token's length when fixed, else -1.
func fixedLen(t hexToken) int {
	switch {
	case t.jump:
		if t.lo == t.hi {
			return t.lo
		}
		return -1
	case t.alts != nil:
		n := -1
		for _, a := range t.alts {
			m := 0
			for _, x := range a {
				l := fixedLen(x)
				if l < 0 {
					return -1
				}
				m += l
			}
			if n >= 0 && m != n {
				return -1
			}
			n = m
		}
		return n
	}
	return 1
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexSeq parses tokens until the end or a ")" or "|" of an alternative.
func hexSeq(s string, depth int) ([]hexToken, string, error) {
	if depth > 4 {
		return nil, s, errors.New("alternatives nested too deeply")
	}
	var out []hexToken
	for s != "" {
		switch c := s[0]; {
		case c == '(':
			var alts [][]hexToken
			s = s[1:]
			for {
				seq, rest, err := hexSeq(s, depth+1)
				if err != nil {
					return nil, s, err
				}
				if len(seq) == 0 {
					return nil, s, errors.New("empty alternative")
				}
				alts = append(alts, seq)
				if rest == "" {
					return nil, rest, errors.New("unterminated alternative")
				}
				s = rest[1:]
				if rest[0] == ')' {
					break
				}
			}
			out = append(out, hexToken{alts: alts})
		case c == ')' || c == '|':
			return out, s, nil
		case c == '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, s, errors.New("unterminated jump")
			}
			lo, hi, err := jumpRange(s[1:end])
			if err != nil {
				return nil, s, err
			}
			out = append(out, hexToken{jump: true, lo: lo, hi: hi})
			s = s[end+1:]
		default:
			if len(s) < 2 {
				return nil, s, errors.New("incomplete byte in hex string")
			}
			t := hexToken{}
			for i, ch := range []byte{s[0], s[1]} {
				shift := uint(4 * (1 - i))
				if ch == '?' {
					continue
				}
				v, ok := hexNibble(ch)
				if !ok {
					return nil, s, fmt.Errorf("bad hex digit %q", ch)
				}
				t.value |= v << shift
				t.mask |= 0xF << shift
			}
			out = append(out, t)
			s = s[2:]
		}
	}
	return out, s, nil
}

func jumpRange(s string) (int, int, error) {
	if s == "-" {
		return 0, maxJump, nil
	}
	lo, hi, ranged := strings.Cut(s, "-")
	a, err := strconv.Atoi(lo)
	if err != nil && !(ranged && lo == "") {
		return 0, 0, fmt.Errorf("bad jump [%s]", s)
	}
	if !ranged {
		return a, a, nil
	}
	if hi == "" {
		return a, maxJump, nil
	}
	b, err := strconv.Atoi(hi)
	if err != nil || b < a || b > maxJump {
		return 0, 0, fmt.Errorf("bad jump [%s]", s)
	}
	return a, b, nil
}

// matchHex returns the length of the hex string matching data at off, or
// -1. Jumps try their shortest length first.
func matchHex(toks []hexToken, data []byte, off int, budget *int) int {
	if len(toks) == 0 {
		return 0
	}
	if *budget--; *budget < 0 {
		return -1
	}
	t := toks[0]
	switch {
	case t.jump:
		for j := t.lo; j <= t.hi && off+j <= len(data); j++ {
			if n := matchHex(toks[1:], data, off+j, budget); n >= 0 {
				return j + n
			}
		}
		return -1
	case t.alts != nil:
		for _, a := range t.alts {
			if n := matchHex(a, data, off, budget); n >= 0 {
				if m := matchHex(toks[1:], data, off+n, budget); m >= 0 {
					return n + m
				}
			}
		}
		return -1
	}
	if off >= len(data) || data[off]&t.mask != t.value&t.mask {
		return -1
	}
	if n := matchHex(toks[1:], data, off+1, budget); n >= 0 {
		return 1 + n
	}
	return -1
}

// compileRegex compiles a regular expression string. Data is read byte by byte
// as characters U+0000 to U+00FF, so \xNN and . match single bytes.
func (p *pattern) compileRegex(src, flags string, mods []string) error {
	for _, m := range mods {
		switch m {
		case "nocase":
			p.nocase = true
		case "fullword":
			p.fullword = true
		case "private":
			p.private = true
		case "ascii":
		default:
			return fmt.Errorf("regular expressions take no %s modifier here", m)
		}
	}
	prefix := ""
	if strings.Contains(flags, "i") || p.nocase {
		prefix += "(?i)"
	}
	if strings.Contains(flags, "s") {
		prefix += "(?s)"
	}
	re, err := regexp.Compile(prefix + src)
	if err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return fmt.Errorf("regular expression: %s", se.Code)
		}
		return err
	}
	anchored, err := regexp.Compile(prefix + `\A(?:` + src + `)`)
	if err != nil {
		return err
	}
	p.re, p.reAnchor = re, anchored
	if lit, _ := re.LiteralPrefix(); len(lit) >= 2 && isLatin1(lit) {
		p.rePrefix = latin1Bytes(lit)
	}
	return nil
}

func isLatin1(s string) bool {
	for _, r := range s {
		if r > 0xFF {
			return false
		}
	}
	return true
}

func latin1Bytes(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r))
	}
	return b
}

// byteReader reads bytes as runes of size 1, so match indices are byte
// offsets.
type byteReader struct {
	b []byte
	i int
}

func (r *byteReader) ReadRune() (rune, int, error) {
	if r.i >= len(r.b) {
		return 0, 0, io.EOF
	}
	r.i++
	return rune(r.b[r.i-1]), 1, nil
}

// maxRegexMatch bounds what a candidate's anchored check reads.
const maxRegexMatch = 4096

// regexAt returns the length of a match starting at off, or -1.
func (p *pattern) regexAt(data []byte, off int) int {
	end := min(len(data), off+maxRegexMatch)
	loc := p.reAnchor.FindReaderIndex(&byteReader{b: data[off:end]})
	if loc == nil {
		return -1
	}
	return loc[1]
}

// regexAll finds the start of every match in data (without a prefix).
func (p *pattern) regexAll(data []byte, each func(off, n int) bool) {
	for start := 0; start < len(data); {
		loc := p.re.FindReaderIndex(&byteReader{b: data[start:]})
		if loc == nil {
			return
		}
		if !each(start+loc[0], loc[1]-loc[0]) {
			return
		}
		start += loc[0] + 1
	}
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// wordBounded checks the fullword modifier for a match at off of n bytes.
func wordBounded(data []byte, off, n int, wide bool) bool {
	step := 1
	if wide {
		step = 2
	}
	if off-step >= 0 && isAlnum(data[off-step]) && (!wide || data[off-step+1] == 0) {
		return false
	}
	if end := off + n; end < len(data) && isAlnum(data[end]) && (!wide || end+1 < len(data) && data[end+1] == 0) {
		return false
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// litAt reports whether lit is at data[off:], ignoring ASCII case when
// nocase is set.
func litAt(data []byte, off int, lit []byte, nocase bool) bool {
	if off < 0 || off+len(lit) > len(data) {
		return false
	}
	for i, c := range lit {
		d := data[off+i]
		if d != c && (!nocase || lower(d) != lower(c)) {
			return false
		}
	}
	return true
}
