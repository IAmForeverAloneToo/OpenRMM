// Package lnktest builds shortcuts and jump lists for tests.
package lnktest

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// When is the shortcut's access time and the jump list entry's last
// access.
var When = time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)

var header = []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

const (
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
)

func ft(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

func u16(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, r)
	}
	return b
}

// Shortcut builds a link to C:\Tools\evil.exe with arguments, a link
// info block, a working directory and a tracker block.
func Shortcut() []byte {
	le := binary.LittleEndian
	b := make([]byte, 76)
	copy(b, header)
	le.PutUint32(b[20:], 0x2|0x10|0x20|0x80)
	le.PutUint32(b[24:], 0x20)
	le.PutUint64(b[28:], ft(When.Add(-time.Hour)))
	le.PutUint64(b[36:], ft(When))
	le.PutUint64(b[44:], ft(When.Add(-30*time.Minute)))
	le.PutUint32(b[52:], 4096)
	// Link info: header 0x1C, volume ID, local base path.
	vol := make([]byte, 16)
	le.PutUint32(vol, 16+5)
	le.PutUint32(vol[4:], 3)
	le.PutUint32(vol[8:], 0xDEADBEEF)
	le.PutUint32(vol[12:], 16)
	vol = append(vol, []byte("DATA\x00")...)
	info := make([]byte, 28)
	le.PutUint32(info[4:], 28)
	le.PutUint32(info[8:], 1)
	le.PutUint32(info[12:], 28)
	le.PutUint32(info[16:], uint32(28+len(vol)))
	info = append(info, vol...)
	info = append(info, []byte("C:\\Tools\\evil.exe\x00")...)
	le.PutUint32(info[24:], uint32(len(info)))
	info = append(info, 0)
	le.PutUint32(info, uint32(len(info)))
	b = append(b, info...)
	for _, s := range []string{`C:\Tools`, "--quiet --steal"} {
		b = le.AppendUint16(b, uint16(len(utf16.Encode([]rune(s)))))
		b = append(b, u16(s)...)
	}
	tracker := make([]byte, 0x60)
	le.PutUint32(tracker, 0x60)
	le.PutUint32(tracker[4:], 0xA0000003)
	copy(tracker[16:], "WS-SOURCE")
	copy(tracker[64+10:], []byte{0x00, 0x15, 0x5d, 0x01, 0x02, 0x03})
	b = append(b, tracker...)
	return append(b, 0, 0, 0, 0)
}

// CFB builds a version 3 compound file whose streams are stored in
// regular sectors (mini stream cutoff 0).
func CFB(streams map[string][]byte) []byte {
	le := binary.LittleEndian
	var sectors [][]byte
	add := func(d []byte) (uint32, int) {
		first := uint32(len(sectors))
		n := 0
		for len(d) > 0 || n == 0 {
			s := make([]byte, 512)
			copy(s, d)
			d = d[min(len(d), 512):]
			sectors = append(sectors, s)
			n++
		}
		return first, n
	}
	type ent struct {
		name  string
		start uint32
		size  int
		typ   byte
	}
	var entries []ent
	var chains [][2]uint32
	entries = append(entries, ent{"Root Entry", endOfChain, 0, 5})
	for name, d := range streams {
		s, n := add(d)
		chains = append(chains, [2]uint32{s, uint32(n)})
		entries = append(entries, ent{name, s, len(d), 2})
	}
	dir := make([]byte, 128*len(entries))
	for i, e := range entries {
		x := dir[128*i:]
		name := u16(e.name)
		copy(x, name)
		le.PutUint16(x[64:], uint16(len(name)+2))
		x[66] = e.typ
		le.PutUint32(x[68:], freeSect)
		le.PutUint32(x[72:], freeSect)
		le.PutUint32(x[76:], freeSect)
		le.PutUint32(x[116:], e.start)
		le.PutUint64(x[120:], uint64(e.size))
	}
	dirStart, dirN := add(dir)
	chains = append(chains, [2]uint32{dirStart, uint32(dirN)})
	fatAt := uint32(len(sectors))
	fat := make([]byte, 512)
	for i := range 128 {
		le.PutUint32(fat[4*i:], freeSect)
	}
	for _, c := range chains {
		for k := range c[1] {
			next := c[0] + k + 1
			if k == c[1]-1 {
				next = endOfChain
			}
			le.PutUint32(fat[4*(c[0]+k):], next)
		}
	}
	le.PutUint32(fat[4*fatAt:], 0xFFFFFFFD)
	sectors = append(sectors, fat)
	h := make([]byte, 512)
	copy(h, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
	le.PutUint16(h[24:], 0x3E)
	le.PutUint16(h[26:], 3)
	le.PutUint16(h[28:], 0xFFFE)
	le.PutUint16(h[30:], 9)
	le.PutUint16(h[32:], 6)
	le.PutUint32(h[44:], 1)
	le.PutUint32(h[48:], dirStart)
	le.PutUint32(h[56:], 0)
	le.PutUint32(h[60:], endOfChain)
	le.PutUint32(h[68:], endOfChain)
	for i := range 109 {
		le.PutUint32(h[76+4*i:], freeSect)
	}
	le.PutUint32(h[76:], fatAt)
	for _, s := range sectors {
		h = append(h, s...)
	}
	return h
}

// DestList builds a version 4 DestList with one entry for stream 1.
func DestList() []byte {
	le := binary.LittleEndian
	d := make([]byte, 32)
	le.PutUint32(d, 4)
	le.PutUint32(d[4:], 1)
	e := make([]byte, 130)
	copy(e[72:], "WS-SOURCE")
	le.PutUint32(e[88:], 1)
	le.PutUint64(e[100:], ft(When))
	le.PutUint32(e[108:], 0)
	le.PutUint32(e[116:], 12)
	path := u16(`C:\Tools\evil.exe`)
	le.PutUint16(e[128:], uint16(len(path)/2))
	return append(append(append(d, e...), path...), 0, 0, 0, 0)
}
