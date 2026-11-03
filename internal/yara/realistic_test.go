package yara

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
	"time"
)

// Rules written the way public rule collections write them.
const realistic = `
rule HKTL_Example_Dumper : hacktool {
   meta:
      description = "Detects a made-up credential dumper by its strings"
      author = "test"
      date = "2026-11-03"
      score = 80
   strings:
      $x1 = "dumpcreds::allsessions" ascii wide nocase
      $x2 = "exampletool-author" ascii wide
      $s1 = "ticket::forge" ascii wide
      $s2 = "secrets::readhive" ascii wide
      $s3 = "rights::elevate" ascii wide
      $op1 = { 33 C0 48 8B ?? ?? ?? 48 85 C9 74 }
   condition:
      uint16(0) == 0x5a4d and filesize < 3MB and ( 1 of ($x*) or 2 of ($s*) or all of ($op*) )
}

rule SUSP_Example_Fetch_And_Run {
   meta:
      description = "A made-up script that fetches and runs text"
   strings:
      $a1 = "Example.Fetcher" ascii wide nocase
      $a2 = "PullText" ascii wide nocase
      $a3 = /RUNIT\s*\(/ nocase
      $b1 = "-packed " ascii wide nocase
   condition:
      filesize < 500KB and ( 2 of ($a*) or $b1 )
}

rule PE_Small_Packed {
   strings:
      $upx0 = "UPX0"
      $upx1 = "UPX1"
   condition:
      uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and all of ($upx*)
}
`

func TestRealisticRules(t *testing.T) {
	rs, err := Compile(realistic)
	if err != nil {
		t.Fatal(err)
	}
	pe := make([]byte, 0x200)
	copy(pe, "MZ")
	pe[0x3c] = 0x80
	copy(pe[0x80:], "PE\x00\x00")
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"dumper", append(append([]byte{}, pe...), []byte("...D\x00U\x00M\x00P\x00C\x00R\x00E\x00D\x00S\x00:\x00:\x00a\x00l\x00l\x00s\x00e\x00s\x00s\x00i\x00o\x00n\x00s\x00")...), "HKTL_Example_Dumper"},
		{"dumper not PE", []byte("dumpcreds::allsessions"), ""},
		{"fetch", []byte("$w = New-Object Example.Fetcher; RunIt ($w.PullText('http://x'))"), "SUSP_Example_Fetch_And_Run"},
		{"upx", append(append([]byte{}, pe...), []byte("UPX0....UPX1")...), "PE_Small_Packed"},
		{"plain", []byte("hello world"), ""},
	}
	for _, c := range cases {
		m, err := rs.Scan(context.Background(), []Block{{Data: c.data}}, int64(len(c.data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, x := range m {
			names = append(names, x.Rule)
		}
		if strings.Join(names, ",") != c.want {
			t.Errorf("%s: got %v, want %q", c.name, names, c.want)
		}
	}
}

// Scanning speed with many rules over a large buffer; run with
// OPENRMM_YARA_SPEED=1.
func TestSpeed(t *testing.T) {
	if os.Getenv("OPENRMM_YARA_SPEED") != "1" {
		t.Skip("set OPENRMM_YARA_SPEED=1")
	}
	var src strings.Builder
	for i := range 300 {
		fmt.Fprintf(&src, "rule r%d { strings: $a = \"marker%05d\" nocase $b = { 4D 5A ?? %02X [1-8] 50 45 } $c = /evil%d[0-9]{3}/ condition: any of them }\n", i, i, i%256, i)
	}
	rs, err := Compile(src.String())
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64<<20)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(r.Uint32())
	}
	start := time.Now()
	m, err := rs.Scan(context.Background(), []Block{{Data: data}}, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("300 rules (900 strings) over 64 MiB: %s, %d matches", time.Since(start).Round(time.Millisecond), len(m))
}
