package response

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// shortcutTarget reads a shell link (.lnk, MS-SHLLINK) for the persistence
// report: its target path and its command-line arguments. Only
// the documented header, link info and string data are read, with every
// offset checked; ok is false for anything else.
func shortcutTarget(b []byte) (target, args string, ok bool) {
	const (
		hasIDList    = 0x1
		hasLinkInfo  = 0x2
		hasName      = 0x4
		hasRelative  = 0x8
		hasWorkDir   = 0x10
		hasArguments = 0x20
		hasIcon      = 0x40
		isUnicode    = 0x80
	)
	if len(b) < 0x4C || binary.LittleEndian.Uint32(b) != 0x4C {
		return "", "", false
	}
	flags := binary.LittleEndian.Uint32(b[20:])
	pos := 0x4C
	if flags&hasIDList != 0 {
		if pos+2 > len(b) {
			return "", "", false
		}
		pos += 2 + int(binary.LittleEndian.Uint16(b[pos:]))
	}
	if flags&hasLinkInfo != 0 {
		if pos+0x1C > len(b) {
			return "", "", false
		}
		info := b[pos:]
		size32 := binary.LittleEndian.Uint32(info)
		header := binary.LittleEndian.Uint32(info[4:])
		if size32 < 0x1C || uint64(size32) > uint64(len(info)) {
			return "", "", false
		}
		size := int(size32)
		info = info[:size]
		if binary.LittleEndian.Uint32(info[8:])&0x1 != 0 {
			base, suffix := "", ""
			if header >= 0x24 && size >= 0x24 {
				base = unicodeZ(info, binary.LittleEndian.Uint32(info[0x1C:]))
				suffix = unicodeZ(info, binary.LittleEndian.Uint32(info[0x20:]))
			}
			if base == "" {
				base = ansiZ(info, binary.LittleEndian.Uint32(info[0x10:]))
				suffix = ansiZ(info, binary.LittleEndian.Uint32(info[0x18:]))
			}
			target = base + suffix
		}
		pos += size
	}
	readString := func() (string, bool) {
		if pos+2 > len(b) {
			return "", false
		}
		n := int(binary.LittleEndian.Uint16(b[pos:]))
		pos += 2
		if flags&isUnicode != 0 {
			if pos+2*n > len(b) {
				return "", false
			}
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(b[pos+2*i:])
			}
			pos += 2 * n
			return string(utf16.Decode(u)), true
		}
		if pos+n > len(b) {
			return "", false
		}
		s := string(b[pos : pos+n])
		pos += n
		return s, true
	}
	var relative string
	for _, f := range []uint32{hasName, hasRelative, hasWorkDir, hasArguments, hasIcon} {
		if flags&f == 0 {
			continue
		}
		s, ok := readString()
		if !ok {
			return target, args, target != ""
		}
		switch f {
		case hasRelative:
			relative = s
		case hasArguments:
			args = s
		}
	}
	if target == "" {
		target = relative
	}
	return clip(target, 1024), clip(args, 4096), target != ""
}

func unicodeZ(b []byte, off uint32) string {
	if off == 0 || uint64(off) >= uint64(len(b)) {
		return ""
	}
	u := []uint16{}
	for i := int(off); i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			return string(utf16.Decode(u))
		}
		u = append(u, c)
	}
	return ""
}

func ansiZ(b []byte, off uint32) string {
	if off == 0 || uint64(off) >= uint64(len(b)) {
		return ""
	}
	s := b[off:]
	if i := strings.IndexByte(string(s), 0); i >= 0 {
		return string(s[:i])
	}
	return ""
}
