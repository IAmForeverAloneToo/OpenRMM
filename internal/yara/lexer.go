// Package yara compiles and runs YARA rules, written for OpenRMM on Go's
// standard library: rules with text, hex and regular expression strings
// (ascii, wide, nocase, fullword, private) and the usual conditions (boolean
// and arithmetic expressions, counts, offsets and lengths of matches, at and
// in, filesize, integer reads, "of" and "for" expressions, references to
// other rules), and the modules in modules.go. Other modules, external
// variables and the xor and base64 modifiers are refused when compiling.
package yara

import (
	"fmt"
	"strconv"
	"strings"
)

type tokenKind int

const (
	tEOF tokenKind = iota
	tIdent
	tString  // "text"
	tHex     // { hex }
	tRegex   // /regex/flags
	tNumber  // 12, 0x1F, 4KB
	tFloat   // 7.25
	tStrID   // $a, $ (anonymous), $a*
	tCount   // #a
	tOffset  // @a
	tLength  // !a
	tPunct   // operators and punctuation
	tKeyword // reserved words
)

var keywords = map[string]bool{
	"all": true, "and": true, "any": true, "ascii": true, "at": true, "base64": true, "base64wide": true, "condition": true,
	"contains": true, "defined": true, "endswith": true, "entrypoint": true, "false": true, "filesize": true, "for": true,
	"fullword": true, "global": true, "icontains": true, "iendswith": true, "iequals": true, "import": true, "in": true,
	"include": true, "istartswith": true, "matches": true, "meta": true, "none": true, "nocase": true, "not": true,
	"of": true, "or": true, "private": true, "rule": true, "startswith": true, "strings": true, "them": true, "true": true,
	"wide": true, "xor": true,
}

type token struct {
	kind  tokenKind
	text  string
	num   int64
	f     float64
	line  int
	flags string // regex flags
}

func (t token) String() string {
	switch t.kind {
	case tEOF:
		return "end of rules"
	case tString:
		return strconv.Quote(t.text)
	}
	return t.text
}

// Error is a compile error with the line it is on.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

type lexer struct {
	src  string
	pos  int
	line int
}

func (l *lexer) errorf(format string, args ...any) error {
	return &Error{Line: l.line, Msg: fmt.Sprintf(format, args...)}
}

// tokens splits a source into tokens. Hex strings are recognized by what
// follows "=" in a strings section: after "=" a "{" starts a hex string. A
// "/" always starts a regular expression (YARA has no division by "/";
// comments are skipped before).
func lex(src string) ([]token, error) {
	l := &lexer{src: src, line: 1}
	var out []token
	afterAssign := false
	for {
		if err := l.skip(); err != nil {
			return nil, err
		}
		if l.pos >= len(l.src) {
			out = append(out, token{kind: tEOF, line: l.line})
			return out, nil
		}
		t, err := l.next(afterAssign)
		if err != nil {
			return nil, err
		}
		afterAssign = t.kind == tPunct && t.text == "="
		out = append(out, t)
	}
}

// skip passes whitespace and comments.
func (l *lexer) skip() error {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				return l.errorf("unterminated comment")
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end], "\n")
			l.pos += end + 4
		default:
			return nil
		}
	}
	return nil
}

func isIdent(c byte, first bool) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || !first && c >= '0' && c <= '9'
}

func (l *lexer) next(afterAssign bool) (token, error) {
	start, line := l.pos, l.line
	c := l.src[l.pos]
	switch {
	case c == '"':
		s, err := l.quoted()
		return token{kind: tString, text: s, line: line}, err
	case c == '{' && afterAssign:
		end := strings.IndexByte(l.src[l.pos:], '}')
		if end < 0 {
			return token{}, l.errorf("unterminated hex string")
		}
		body := l.src[l.pos+1 : l.pos+end]
		l.line += strings.Count(body, "\n")
		l.pos += end + 1
		return token{kind: tHex, text: body, line: line}, nil
	case c == '/':
		return l.regex()
	case c == '$' || c == '#' || c == '@' || c == '!' && l.pos+1 < len(l.src) && isIdent(l.src[l.pos+1], true):
		l.pos++
		for l.pos < len(l.src) && isIdent(l.src[l.pos], false) {
			l.pos++
		}
		if c == '$' && l.pos < len(l.src) && l.src[l.pos] == '*' {
			l.pos++
		}
		kind := map[byte]tokenKind{'$': tStrID, '#': tCount, '@': tOffset, '!': tLength}[c]
		return token{kind: kind, text: l.src[start:l.pos], line: line}, nil
	case c >= '0' && c <= '9':
		return l.number()
	case isIdent(c, true):
		for l.pos < len(l.src) && isIdent(l.src[l.pos], false) {
			l.pos++
		}
		word := l.src[start:l.pos]
		if keywords[word] {
			return token{kind: tKeyword, text: word, line: line}, nil
		}
		return token{kind: tIdent, text: word, line: line}, nil
	}
	for _, op := range []string{"..", "<<", ">>", "<=", ">=", "==", "!="} {
		if strings.HasPrefix(l.src[l.pos:], op) {
			l.pos += len(op)
			return token{kind: tPunct, text: op, line: line}, nil
		}
	}
	if strings.ContainsRune("{}()[]:=,<>+-*\\%&|^~.", rune(c)) {
		l.pos++
		return token{kind: tPunct, text: string(c), line: line}, nil
	}
	return token{}, l.errorf("unexpected character %q", c)
}

// quoted reads a text string with YARA's escapes (\" \\ \n \r \t \xNN).
func (l *lexer) quoted() (string, error) {
	var b strings.Builder
	l.pos++
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch c {
		case '"':
			l.pos++
			return b.String(), nil
		case '\n':
			return "", l.errorf("unterminated text string")
		case '\\':
			if l.pos+1 >= len(l.src) {
				return "", l.errorf("unterminated text string")
			}
			e := l.src[l.pos+1]
			l.pos += 2
			switch e {
			case '"', '\\':
				b.WriteByte(e)
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'x':
				if l.pos+2 > len(l.src) {
					return "", l.errorf("bad \\x escape")
				}
				v, err := strconv.ParseUint(l.src[l.pos:l.pos+2], 16, 8)
				if err != nil {
					return "", l.errorf("bad \\x escape")
				}
				b.WriteByte(byte(v))
				l.pos += 2
			default:
				return "", l.errorf("unknown escape \\%c", e)
			}
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return "", l.errorf("unterminated text string")
}

// regex reads /pattern/flags; a slash inside is escaped as \/.
func (l *lexer) regex() (token, error) {
	line := l.line
	l.pos++
	var b strings.Builder
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			return token{}, l.errorf("unterminated regular expression")
		case c == '\\' && l.pos+1 < len(l.src):
			if l.src[l.pos+1] == '/' {
				b.WriteByte('/')
			} else {
				b.WriteString(l.src[l.pos : l.pos+2])
			}
			l.pos += 2
		case c == '/':
			l.pos++
			start := l.pos
			for l.pos < len(l.src) && (l.src[l.pos] == 'i' || l.src[l.pos] == 's') {
				l.pos++
			}
			return token{kind: tRegex, text: b.String(), flags: l.src[start:l.pos], line: line}, nil
		default:
			b.WriteByte(c)
			l.pos++
		}
	}
	return token{}, l.errorf("unterminated regular expression")
}

// number reads a decimal or hexadecimal integer with an optional KB or MB
// suffix, or a decimal number with a fraction (7.25; "1..5" is a range).
func (l *lexer) number() (token, error) {
	start, line := l.pos, l.line
	base := 10
	if strings.HasPrefix(l.src[l.pos:], "0x") || strings.HasPrefix(l.src[l.pos:], "0X") {
		base = 16
		l.pos += 2
	} else if strings.HasPrefix(l.src[l.pos:], "0o") {
		base = 8
		l.pos += 2
	}
	digits := l.pos
	for l.pos < len(l.src) && (l.src[l.pos] >= '0' && l.src[l.pos] <= '9' || base == 16 && strings.ContainsRune("abcdefABCDEF", rune(l.src[l.pos]))) {
		l.pos++
	}
	if base == 10 && l.pos+1 < len(l.src) && l.src[l.pos] == '.' && l.src[l.pos+1] >= '0' && l.src[l.pos+1] <= '9' {
		l.pos++
		for l.pos < len(l.src) && l.src[l.pos] >= '0' && l.src[l.pos] <= '9' {
			l.pos++
		}
		f, err := strconv.ParseFloat(l.src[start:l.pos], 64)
		if err != nil || l.pos < len(l.src) && isIdent(l.src[l.pos], false) {
			return token{}, l.errorf("bad number %q", l.src[start:l.pos])
		}
		return token{kind: tFloat, text: l.src[start:l.pos], f: f, line: line}, nil
	}
	v, err := strconv.ParseInt(l.src[digits:l.pos], base, 64)
	if err != nil {
		return token{}, l.errorf("bad number %q", l.src[start:l.pos])
	}
	switch {
	case strings.HasPrefix(l.src[l.pos:], "KB"):
		v <<= 10
		l.pos += 2
	case strings.HasPrefix(l.src[l.pos:], "MB"):
		v <<= 20
		l.pos += 2
	}
	if l.pos < len(l.src) && isIdent(l.src[l.pos], false) {
		return token{}, l.errorf("bad number %q", l.src[start:l.pos+1])
	}
	return token{kind: tNumber, text: l.src[start:l.pos], num: v, line: line}, nil
}
