package protocol

import (
	"strconv"
	"strings"
	"testing"
)

// Pasted indicator lists are typed, canonicalized and checked.
func TestParseIndicators(t *testing.T) {
	text := strings.Join([]string{
		"# comment",
		"",
		strings.Repeat("A", 64),
		strings.Repeat("b", 40),
		strings.Repeat("c", 32),
		"10.1.2.3",
		"::ffff:192.0.2.1",
		"198.51.100.7/24",
		`C:\Users\*\AppData\evil.exe`,
		"evil.com",
		"domain:Bad.Example.COM.",
		"domain,*.example.org",
		"cmd:-EncodedCommand",
		"name:mimikatz*.exe",
		"*.hta",
		"sha256,zz",
		"domain:*.com",
		"ip:300.1.1.1",
		"not a valid ip 999.1.1.1/77 x",
		strings.Repeat("a", 64),
	}, "\r\n")
	list, problems := ParseIndicators(text)
	want := []Indicator{
		{"sha256", strings.Repeat("a", 64)},
		{"sha1", strings.Repeat("b", 40)},
		{"md5", strings.Repeat("c", 32)},
		{"ip", "10.1.2.3"},
		{"ip", "192.0.2.1"},
		{"ip", "198.51.100.0/24"},
		{"path", `C:\Users\*\AppData\evil.exe`},
		{"name", "evil.com"},
		{"domain", "bad.example.com"},
		{"domain", "*.example.org"},
		{"cmd", "-EncodedCommand"},
		{"name", "mimikatz*.exe"},
		{"name", "*.hta"},
	}
	if len(list) != len(want) {
		t.Fatalf("got %v problems %v", list, problems)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Fatalf("%d: %v want %v", i, list[i], want[i])
		}
	}
	if len(problems) != 4 || !strings.HasPrefix(problems[0], "line 16:") {
		t.Fatal("problems", problems)
	}
	if !(HuntSpec{Indicators: list}).Valid() {
		t.Fatal("parsed list invalid")
	}
	for _, bad := range []Indicator{
		{"sha256", strings.Repeat("A", 64)},
		{"ip", "10.1.2.3/8"},
		{"ip", "0.0.0.0/0"},
		{"name", `a\b`},
		{"name", "*"},
		{"path", `C:\`},
		{"path", `C:\*`},
		{"path", `not a path 1.2.3.4/77 x`},
		{"path", `C:\Users\*\%TEMP%`},
		{"path", `\Windows\Temp\x.exe`},
		{"domain", "*.com"},
		{"domain", "Example.com"},
		{"cmd", "ab"},
		{"cmd", "a\nb"},
		{"other", "x"},
	} {
		if bad.Valid() {
			t.Fatal("accepted", bad)
		}
	}
	if (HuntSpec{}).Valid() || (HuntSpec{Indicators: []Indicator{want[0], want[0]}}).Valid() {
		t.Fatal("empty or repeated list accepted")
	}
	a := ResponseAction{Kind: "hunt", Hunt: &HuntSpec{Indicators: want, Files: true}}
	if !a.Valid() || a.Label() != "Indicator hunt (13 indicators)" {
		t.Fatal("action", a.Label())
	}
	if parsed, ok := ParseAction(a.Text()); !ok || len(parsed.Hunt.Indicators) != 13 {
		t.Fatal("round trip")
	}
	if (ResponseAction{Kind: "processes", Hunt: a.Hunt}).Valid() || (ResponseAction{Kind: "hunt", Hunt: a.Hunt, Key: "HKLM"}).Valid() {
		t.Fatal("hunt spec on another action accepted")
	}
	big := HuntSpec{}
	for n := range 300 {
		big.Indicators = append(big.Indicators, Indicator{"cmd", strings.Repeat("x", 500) + strconv.Itoa(n)})
	}
	if big.Valid() {
		t.Fatal("over the indicator size limit")
	}
}
