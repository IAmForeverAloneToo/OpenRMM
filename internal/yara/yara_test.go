package yara

import (
	"context"
	"math/rand/v2"
	"strings"
	"testing"
)

// matches compiles rules and returns the names of those matching data.
func matches(t *testing.T, src string, data []byte) []string {
	t.Helper()
	rs, err := Compile(src)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, src)
	}
	m, err := rs.Scan(context.Background(), []Block{{Data: data}}, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range m {
		names = append(names, x.Rule)
	}
	return names
}

func expect(t *testing.T, cond, data string, want bool) {
	t.Helper()
	src := "rule r { strings:\n $a = \"evil\"\n $b = { 4D 5A }\n $c = \"Evil\" nocase\n condition: (" + cond + ") and ($a or $b or $c or true) }"
	got := len(matches(t, src, []byte(data))) == 1
	if got != want {
		t.Errorf("%q on %q: got %v, want %v", cond, data, got, want)
	}
}

func TestTextStrings(t *testing.T) {
	cases := []struct {
		str, data string
		want      bool
	}{
		{`"evil"`, "an evil thing", true},
		{`"evil"`, "an EVIL thing", false},
		{`"evil" nocase`, "an EVIL thing", true},
		{`"evil" wide`, "a\x00n\x00 \x00e\x00v\x00i\x00l\x00", true},
		{`"evil" wide`, "evil", false},
		{`"evil" wide ascii`, "evil", true},
		{`"evil" fullword`, "an evil.dll", true},
		{`"evil" fullword`, "devilish", false},
		{`"evil" fullword`, "evil", true},
		{`"evil" wide fullword`, "d\x00e\x00v\x00i\x00l\x00", false},
		{`"evil" wide fullword`, "-\x00e\x00v\x00i\x00l\x00", true},
		{`"a\x00b\"c"`, "xa\x00b\"cx", true},
	}
	for _, c := range cases {
		src := "rule r { strings: $a = " + c.str + " condition: $a }"
		if got := len(matches(t, src, []byte(c.data))) == 1; got != c.want {
			t.Errorf("%s on %q: got %v", c.str, c.data, got)
		}
	}
}

func TestHexStrings(t *testing.T) {
	cases := []struct {
		hex, data string
		want      bool
	}{
		{"{ 4D 5A 90 00 }", "xxMZ\x90\x00", true},
		{"{ 4D 5A ?? 00 }", "MZ\xff\x00", true},
		{"{ 4D 5A ?? 00 }", "MZ\xff\x01", false},
		{"{ 4D 5A 9? 00 }", "MZ\x95\x00", true},
		{"{ 4D 5A ?0 00 }", "MZ\x95\x00", false},
		{"{ 4D 5A [2-4] 50 45 }", "MZ..PE", true},
		{"{ 4D 5A [2-4] 50 45 }", "MZ.....PE", false},
		{"{ 4D 5A [-] 50 45 }", "MZ" + strings.Repeat("x", 1000) + "PE", true},
		{"{ 4D 5A ( 01 02 | 03 ) 50 }", "MZ\x03P", true},
		{"{ 4D 5A ( 01 02 | 03 ) 50 }", "MZ\x01\x02P", true},
		{"{ 4D 5A ( 01 02 | 03 ) 50 }", "MZ\x01P", false},
		// No atom: starts with a wildcard byte.
		{"{ ?? 5A }", "MZ", true},
		{"{ ?? 5B }", "MZ", false},
	}
	for _, c := range cases {
		src := "rule r { strings: $a = " + c.hex + " condition: $a }"
		if got := len(matches(t, src, []byte(c.data))) == 1; got != c.want {
			t.Errorf("%s on %q: got %v", c.hex, c.data, got)
		}
	}
}

func TestRegex(t *testing.T) {
	cases := []struct {
		re, data string
		want     bool
	}{
		{`/md5: [0-9a-f]{32}/`, "md5: d41d8cd98f00b204e9800998ecf8427e", true},
		{`/md5: [0-9a-f]{32}/`, "md5: d41d8cd9", false},
		{`/[a-z]+\.onion/`, "visit abcdef.onion now", true},
		{`/EVIL/i`, "so evil", true},
		{`/EVIL/`, "so evil", false},
		{`/\x90{4}/`, "a\x90\x90\x90\x90b", true},
		{`/a.b/`, "a\nb", false},
		{`/a.b/s`, "a\nb", true},
		{`/evil/ fullword`, "devil", false},
		{`/https?:\/\/[a-z]+/`, "get http://evil", true},
	}
	for _, c := range cases {
		src := "rule r { strings: $a = " + c.re + " condition: $a }"
		if got := len(matches(t, src, []byte(c.data))) == 1; got != c.want {
			t.Errorf("%s on %q: got %v", c.re, c.data, got)
		}
	}
}

func TestConditions(t *testing.T) {
	data := "MZ evil ... evil ... EVIL"
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"$a and $b", true},
		{"#a == 2", true},
		{"#c == 3", true},
		{"$b at 0", true},
		{"$a at 3", true},
		{"$a at 4", false},
		{"$a in (0..5)", true},
		{"$a in (4..10)", false},
		{"@a[1] == 3 and @a[2] == 12", true},
		{"!a[1] == 4", true},
		{"@a[3] == 0", false},           // undefined
		{"not (@a[3] == 0)", false},     // not undefined is undefined
		{"defined @a[2]", true},         // defined
		{"defined @a[3]", false},        // undefined
		{"filesize == 25", true},        // size
		{"filesize < 1KB", true},        // suffix
		{"uint16(0) == 0x5A4D", true},   // little-endian read
		{"uint16be(0) == 0x4D5A", true}, // big-endian read
		{"uint32(1000) == 0", false},    // out of range is undefined
		{"int8(0) == 77", true},
		{"#a in (0..10) == 1", true},
		{"2 of them", true},
		{"all of them", true},
		{"any of ($a, $c)", true},
		{"none of ($a*)", false},
		{"3 of ($a, $b, $c)", true},
		{"50% of them", true},
		{"for all of ($a, $c) : (# >= 2)", true},
		{"for any of them : ($ at 0)", true},
		{"for all i in (1..#a) : (@a[i] < 20)", true},
		{"for any i in (1..#a) : (@a[i] > 20)", false},
		{"for 2 i in (3, 12, 99) : ($a at i)", true},
		{"(1 + 2) * 3 == 9 and 7 \\ 2 == 3 and 7 % 2 == 1", true},
		{"0x0F & 0x3 == 3 and 1 << 4 == 16 and -1 < 0 and ~0 == -1", true},
		{"1 \\ 0 == 0", false},
		{`"abc" contains "b" and "ABC" icontains "b" and "abc" startswith "ab"`, true},
		{`"abc" matches /^a.c$/`, true},
		{"true and not false", true},
	} {
		expect(t, c.cond, data, c.want)
	}
}

func TestRulesAndMeta(t *testing.T) {
	src := `
private rule is_pe { condition: uint16(0) == 0x5A4D }
rule evil_pe : malware windows {
	meta:
		author = "test"
		score = 75
		active = true
	strings:
		$s = "evil"
	condition:
		is_pe and $s
}
rule either { condition: any of (is_pe, evil_pe) }
`
	rs, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := rs.Scan(context.Background(), []Block{{Data: []byte("MZ...evil...")}}, 12)
	if len(m) != 2 || m[0].Rule != "evil_pe" || m[1].Rule != "either" {
		t.Fatalf("%+v", m)
	}
	if strings.Join(m[0].Tags, ",") != "malware,windows" || len(m[0].Meta) != 3 || m[0].Meta[1].Value != int64(75) || m[0].Meta[2].Value != true {
		t.Fatalf("%+v", m[0])
	}
	if s := m[0].Strings; len(s) != 1 || s[0].ID != "$s" || s[0].Offset != 5 || s[0].Length != 4 || string(s[0].Data) != "evil" {
		t.Fatalf("%+v", s)
	}
	// A global rule that fails stops every rule.
	g := "global rule big { condition: filesize > 100 }\nrule any_data { condition: true }"
	if got := matches(t, g, []byte("small")); len(got) != 0 {
		t.Fatal("global rule ignored", got)
	}
}

// Process memory is scanned in blocks at their addresses; filesize is
// undefined there.
func TestBlocks(t *testing.T) {
	rs, err := Compile(`rule r { strings: $a = "evil" condition: $a at 0x10004 and not defined filesize }`)
	if err != nil {
		t.Fatal(err)
	}
	m, err := rs.Scan(context.Background(), []Block{{Base: 0x1000, Data: []byte("nothing")}, {Base: 0x10000, Data: []byte("....evil")}}, -1)
	if err != nil || len(m) != 1 || m[0].Strings[0].Offset != 0x10004 {
		t.Fatal(m, err)
	}
}

func TestCompileErrors(t *testing.T) {
	for src, want := range map[string]string{
		`import "elf" rule r { condition: true }`:               "module",
		`rule r { condition: pe.number_of_sections == 1 }`:      "without import",
		`rule r { strings: $a = "x" condition: true }`:          "never used",
		`rule r { condition: $a }`:                              "undefined string",
		`rule r { strings: $a = "x" xor condition: $a }`:        "xor",
		`rule r { condition: true } rule r { condition: true }`: "duplicate rule",
		`rule r { strings: $a = { 4D 5A [2-] } condition: $a }`: "jump",
		`rule r { strings: $a = /(a)\1/ condition: $a }`:        "regular expression",
		`rule r { strings: $a = "x" $a = "y" condition: $a }`:   "duplicate string",
		`rule r { condition: missing_rule }`:                    "unknown identifier",
		`rule r { strings: $a = "unterminated condition: $a }`:  "unterminated",
		`include "other.yar"`:                                   "include",
		``:                                                      "no rules",
	} {
		_, err := Compile(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
}

// Random sources and data never panic.
func TestRandom(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 12))
	good := `rule r { strings: $a = "evil" nocase $b = { 4D ?? [1-3] (5A | 90 90) } $c = /x[0-9]+y/ condition: (#a > 1 or $b) and for any i in (1..#c) : (!c[i] > 2) and uint32(@a[1]) != 0 }`
	alphabet := []byte("rule{}()[]$#@!:=\"/ab?4D5A|-..ofanyallthemand or not0123456789\n")
	for range 3000 {
		src := []byte(good)
		for range 1 + r.IntN(6) {
			src[r.IntN(len(src))] = alphabet[r.IntN(len(alphabet))]
		}
		rs, err := Compile(string(src))
		if err != nil {
			continue
		}
		data := make([]byte, r.IntN(300))
		for i := range data {
			data[i] = "evilMZxy0123\x90"[r.IntN(13)]
		}
		_, _ = rs.Scan(context.Background(), []Block{{Data: data}}, int64(len(data)))
	}
}

// A canceled scan stops.
func TestCanceled(t *testing.T) {
	rs, _ := Compile(`rule r { strings: $a = "x" condition: $a }`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rs.Scan(ctx, []Block{{Data: make([]byte, 3<<20)}}, 3<<20); err == nil {
		t.Fatal("not stopped")
	}
}
