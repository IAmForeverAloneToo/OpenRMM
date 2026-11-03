package prefetch

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"time"
	"unicode/utf16"
)

var when = time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)

func ft(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

func u16(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// build makes an uncompressed prefetch file of a version, with the second
// version 30 layout (run count at 200) when short is set.
func build(version int, short bool) []byte {
	le := binary.LittleEndian
	b := make([]byte, 0x400)
	le.PutUint32(b, uint32(version))
	copy(b[4:], "SCCA")
	copy(b[16:], u16("NOTEPAD.EXE"))
	le.PutUint32(b[76:], 0xCAFE1234)
	metrics := uint32(0x130)
	if short {
		metrics = 0x128
	}
	le.PutUint32(b[84:], metrics)
	files := u16(`\VOLUME{01d0}\WINDOWS\SYSTEM32\NTDLL.DLL` + "\x00" + `\VOLUME{01d0}\WINDOWS\SYSTEM32\NOTEPAD.EXE` + "\x00")
	copy(b[0x200:], files)
	le.PutUint32(b[100:], 0x200)
	le.PutUint32(b[104:], uint32(len(files)))
	// One volume entry plus its device path.
	entry := map[int]int{17: 40, 23: 104, 26: 104, 30: 96, 31: 96}[version]
	vol := make([]byte, entry)
	dev := u16(`\VOLUME{01d0}`)
	le.PutUint32(vol, uint32(entry))
	le.PutUint32(vol[4:], uint32(len(dev)/2))
	le.PutUint64(vol[8:], ft(when.Add(-24*time.Hour)))
	le.PutUint32(vol[16:], 0xA1B2C3D4)
	area := append(vol, dev...)
	copy(b[0x300:], area)
	le.PutUint32(b[108:], 0x300)
	le.PutUint32(b[112:], 1)
	le.PutUint32(b[116:], uint32(len(area)))
	runs, count := map[int]int{17: 120, 23: 128}[version], map[int]int{17: 144, 23: 152}[version]
	if version >= 26 {
		runs, count = 128, 208
		if short {
			count = 200
		}
	}
	le.PutUint64(b[runs:], ft(when))
	if version >= 26 {
		le.PutUint64(b[runs+8:], ft(when.Add(-time.Hour)))
	}
	le.PutUint32(b[count:], 42)
	le.PutUint32(b[12:], uint32(len(b)))
	return b
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		version int
		short   bool
		runs    int
	}{{17, false, 1}, {23, false, 1}, {26, false, 2}, {30, false, 2}, {30, true, 2}, {31, true, 2}} {
		i, err := Parse(build(c.version, c.short))
		if err != nil {
			t.Fatal(c, err)
		}
		if i.Version != c.version || i.Executable != "NOTEPAD.EXE" || i.Hash != 0xCAFE1234 || i.RunCount != 42 || len(i.Runs) != c.runs || !i.Runs[0].Equal(when) {
			t.Fatalf("%+v: %+v", c, i)
		}
		if len(i.Files) != 2 || i.Path() != `\VOLUME{01d0}\WINDOWS\SYSTEM32\NOTEPAD.EXE` {
			t.Fatal(c, i.Files)
		}
		if len(i.Volumes) != 1 || i.Volumes[0].Device != `\VOLUME{01d0}` || i.Volumes[0].Serial != 0xA1B2C3D4 || !i.Volumes[0].Created.Equal(when.Add(-24*time.Hour)) {
			t.Fatal(c, i.Volumes)
		}
	}
}

// A hand-built block. The match symbol 0x113 (length 3+3, one offset bit)
// has a 1-bit code and every literal a 9-bit code, a complete code: 2^14 +
// 256 * 2^6 = 2^15 table slots. Canonically the match symbol is "0" and
// literal s is "1" followed by the 8 bits of s.
func TestHuffmanBlock(t *testing.T) {
	in := make([]byte, 256)
	for s := range 256 {
		in[s/2] |= 9 << (4 * (s % 2))
	}
	in[0x113/2] |= 1 << (4 * (0x113 % 2))
	var bits []int
	lit := func(c byte) {
		bits = append(bits, 1)
		for k := 7; k >= 0; k-- {
			bits = append(bits, int(c>>k)&1)
		}
	}
	lit('a')
	lit('b')
	lit('c')
	bits = append(bits, 0, 1) // the match; offset bit 1 means 1 + 2 = 3
	lit('!')
	for len(bits)%16 != 0 {
		bits = append(bits, 0)
	}
	// Bits are packed most significant first into 16-bit little-endian
	// words.
	for w := 0; w < len(bits); w += 16 {
		var v uint16
		for k := range 16 {
			v = v<<1 | uint16(bits[w+k])
		}
		in = binary.LittleEndian.AppendUint16(in, v)
	}
	out, err := decompressHuffman(in, 10)
	if err != nil || string(out) != "abcabcabc!" {
		t.Fatalf("%q %v", out, err)
	}
	// A match reaching before the start of the output is refused.
	bad := append([]byte(nil), in...)
	bad[256], bad[257] = 0, 0
	if _, err := decompressHuffman(bad, 10); err == nil {
		t.Fatal("match before the start accepted")
	}
	// So is an incomplete code.
	if _, err := decompressHuffman(make([]byte, 300), 10); err == nil {
		t.Fatal("empty table accepted")
	}
}

// Random and truncated input never panics.
func TestDamagedInput(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	good := build(30, false)
	for range 3000 {
		b := append([]byte(nil), good...)
		switch r.IntN(3) {
		case 0:
			b = b[:r.IntN(len(b))]
		case 1:
			for range 1 + r.IntN(20) {
				b[r.IntN(len(b))] = byte(r.Uint32())
			}
		case 2:
			b = append([]byte("MAM\x04"), make([]byte, 4+r.IntN(600))...)
			binary.LittleEndian.PutUint32(b[4:], uint32(r.IntN(100000)))
			for k := 8; k < len(b); k++ {
				b[k] = byte(r.Uint32())
			}
		}
		_, _ = Parse(b)
	}
}
