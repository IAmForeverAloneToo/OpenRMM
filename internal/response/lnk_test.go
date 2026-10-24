package response

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// A shortcut's target and arguments are read from its link info and
// string data; damaged files are refused.
func TestShortcutTarget(t *testing.T) {
	le := binary.LittleEndian
	header := make([]byte, 0x4C)
	le.PutUint32(header, 0x4C)
	le.PutUint32(header[20:], 0x2|0x20|0x80) // link info, arguments, Unicode
	base := []byte(`C:\Users\Public\evil.exe` + "\x00")
	info := make([]byte, 0x1C)
	le.PutUint32(info[4:], 0x1C) // header size: no Unicode offsets
	le.PutUint32(info[8:], 0x1)  // VolumeIDAndLocalBasePath
	le.PutUint32(info[0x10:], 0x1C)
	le.PutUint32(info[0x18:], uint32(0x1C+len(base)))
	info = append(info, base...)
	info = append(info, 0) // empty common path suffix
	le.PutUint32(info, uint32(len(info)))
	arg := utf16.Encode([]rune("-enc AAAA"))
	args := make([]byte, 2+2*len(arg))
	le.PutUint16(args, uint16(len(arg)))
	for i, c := range arg {
		le.PutUint16(args[2+2*i:], c)
	}
	lnk := append(append(append([]byte{}, header...), info...), args...)
	target, a, ok := shortcutTarget(lnk)
	if !ok || target != `C:\Users\Public\evil.exe` || a != "-enc AAAA" {
		t.Fatalf("%q %q %v", target, a, ok)
	}
	for _, bad := range [][]byte{nil, header[:20], append(append([]byte{}, header...), 0xFF, 0xFF, 0xFF, 0x7F)} {
		if _, _, ok := shortcutTarget(bad); ok {
			t.Fatal("damaged shortcut read", bad)
		}
	}
	// A truncated argument string still yields the target.
	if target, _, ok := shortcutTarget(lnk[:len(lnk)-3]); !ok || target == "" {
		t.Fatal("target of a truncated shortcut")
	}
}
