package yara

import (
	"context"
	"math/rand/v2"
	"os"
	"testing"
	"time"
)

// Scanning speed with two plain strings (as in a small rule set) over a
// large buffer; run with OPENRMM_YARA_SPEED=1.
func TestSpeedSmall(t *testing.T) {
	if os.Getenv("OPENRMM_YARA_SPEED") != "1" {
		t.Skip("set OPENRMM_YARA_SPEED=1")
	}
	rs, err := Compile(`rule a { strings: $a = "openrmm-yara-check-0123456789ab" condition: $a }
rule b { strings: $w = "openrmm-yara-check-0123456789ab" wide condition: $w }`)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256<<20)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		// Mostly text-like bytes, as process memory often is.
		data[i] = "abcdefghijklmnop\x00\x00\x00\x00ORMyar0123"[r.IntN(30)]
	}
	start := time.Now()
	if _, err := rs.Scan(context.Background(), []Block{{Data: data}}, -1); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("2 strings over 256 MiB: %s (%.0f MB/s)", took.Round(time.Millisecond), 256/took.Seconds())
}
