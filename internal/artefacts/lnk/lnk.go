// Package lnk reads Windows shortcut files (.lnk, MS-SHLLINK) and jump
// lists (automatic ones, OLE compound files with a DestList, and custom
// ones): the target's path, arguments, times, size and volume, and the
// machine the shortcut was made on. It uses only the standard library;
// every offset is checked before use.
package lnk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// ErrCorrupt reports data that is not a shortcut.
var ErrCorrupt = errors.New("lnk: not a shortcut file")

// MaxFile is the largest shortcut or jump list read.
const MaxFile = 64 << 20

var le = binary.LittleEndian

// Header is the shell link header's size and CLSID, which every shortcut
// starts with.
var Header = []byte{0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46}

// Link flags.
const (
	hasIDList       = 0x1
	hasLinkInfo     = 0x2
	hasName         = 0x4
	hasRelativePath = 0x8
	hasWorkingDir   = 0x10
	hasArguments    = 0x20
	hasIconLocation = 0x40
	isUnicode       = 0x80
)

// Link is a decoded shortcut.
type Link struct {
	TargetPath   string
	Arguments    string
	WorkingDir   string
	RelativePath string
	Name         string
	IconLocation string
	Created      time.Time
	Accessed     time.Time
	Modified     time.Time
	Size         uint32
	Attributes   uint32
	DriveType    string
	VolumeSerial string
	VolumeLabel  string
	NetworkPath  string
	// MachineID is the NetBIOS name of the machine the target was on, and
	// MAC the network address in its distributed link tracking ID.
	MachineID string
	MAC       string
}

var driveTypes = []string{"Unknown", "No root", "Removable", "Fixed", "Network", "CD-ROM", "RAM disk"}

// Parse decodes a shortcut from the start of b.
func Parse(b []byte) (Link, error) {
	if len(b) < 76 || string(b[:20]) != string(Header) {
		return Link{}, ErrCorrupt
	}
	flags := le.Uint32(b[20:])
	l := Link{
		Attributes: le.Uint32(b[24:]),
		Created:    filetime(le.Uint64(b[28:])),
		Accessed:   filetime(le.Uint64(b[36:])),
		Modified:   filetime(le.Uint64(b[44:])),
		Size:       le.Uint32(b[52:]),
	}
	pos := 76
	if flags&hasIDList != 0 {
		if pos+2 > len(b) {
			return l, ErrCorrupt
		}
		pos += 2 + int(le.Uint16(b[pos:]))
	}
	if flags&hasLinkInfo != 0 {
		if pos+4 > len(b) {
			return l, ErrCorrupt
		}
		size := int(le.Uint32(b[pos:]))
		if size < 28 || pos+size > len(b) {
			return l, ErrCorrupt
		}
		l.linkInfo(b[pos : pos+size])
		pos += size
	}
	for _, s := range []struct {
		flag uint32
		to   *string
	}{{hasName, &l.Name}, {hasRelativePath, &l.RelativePath}, {hasWorkingDir, &l.WorkingDir}, {hasArguments, &l.Arguments}, {hasIconLocation, &l.IconLocation}} {
		if flags&s.flag == 0 {
			continue
		}
		if pos+2 > len(b) {
			return l, ErrCorrupt
		}
		n := int(le.Uint16(b[pos:]))
		pos += 2
		if flags&isUnicode != 0 {
			n *= 2
		}
		if pos+n > len(b) {
			return l, ErrCorrupt
		}
		if flags&isUnicode != 0 {
			*s.to = utf16s(b[pos : pos+n])
		} else {
			*s.to = latin1(b[pos : pos+n])
		}
		pos += n
	}
	// Extra data blocks until a terminal block.
	for pos+8 <= len(b) {
		size := int(le.Uint32(b[pos:]))
		if size < 8 || pos+size > len(b) {
			break
		}
		block := b[pos : pos+size]
		switch le.Uint32(block[4:]) {
		case 0xA0000003: // distributed link tracking
			if size >= 0x60 {
				l.MachineID = cstring(block[16:32])
				// The file's object ID is a version 1 UUID: its last six
				// bytes are a network address.
				obj := block[64:80]
				l.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", obj[10], obj[11], obj[12], obj[13], obj[14], obj[15])
			}
		case 0xA0000001: // environment variable target
			if l.TargetPath == "" && size >= 788 {
				if t := utf16z(block[268:788]); t != "" {
					l.TargetPath = t
				} else {
					l.TargetPath = cstring(block[8:268])
				}
			}
		}
		pos += size
	}
	if l.TargetPath == "" && l.RelativePath != "" {
		l.TargetPath = l.RelativePath
	}
	return l, nil
}

func (l *Link) linkInfo(info []byte) {
	header := int(le.Uint32(info[4:]))
	flags := le.Uint32(info[8:])
	at := func(off int) int {
		o := int(le.Uint32(info[off:]))
		if o <= 0 || o >= len(info) {
			return -1
		}
		return o
	}
	var base, suffix string
	if flags&1 != 0 {
		if v := at(12); v >= 0 && v+16 <= len(info) {
			vol := info[v:]
			if t := int(le.Uint32(vol[4:])); t < len(driveTypes) {
				l.DriveType = driveTypes[t]
			}
			l.VolumeSerial = fmt.Sprintf("%08X", le.Uint32(vol[8:]))
			if lo := int(le.Uint32(vol[12:])); lo == 0x14 && len(vol) >= 20 {
				if u := int(le.Uint32(vol[16:])); u > 0 && u < len(vol) {
					l.VolumeLabel = utf16z(vol[u:])
				}
			} else if lo > 0 && lo < len(vol) {
				l.VolumeLabel = cstring(vol[lo:])
			}
		}
		if p := at(16); p >= 0 {
			base = cstring(info[p:])
		}
		if header >= 0x24 && len(info) >= 0x24 {
			if p := at(28); p >= 0 {
				base = utf16z(info[p:])
			}
		}
	}
	if flags&2 != 0 {
		if n := at(20); n >= 0 && n+20 <= len(info) {
			net := info[n:]
			if o := int(le.Uint32(net[8:])); o > 0 && o < len(net) {
				l.NetworkPath = cstring(net[o:])
			}
		}
	}
	if p := at(24); p >= 0 {
		suffix = cstring(info[p:])
	}
	if header >= 0x24 && len(info) >= 0x24 {
		if p := at(32); p >= 0 {
			suffix = utf16z(info[p:])
		}
	}
	switch {
	case base != "":
		l.TargetPath = base + suffix
	case l.NetworkPath != "":
		l.TargetPath = strings.TrimSuffix(l.NetworkPath, `\`)
		if suffix != "" {
			l.TargetPath += `\` + suffix
		}
	}
}

func filetime(v uint64) time.Time {
	const epoch = 116444736000000000
	if v <= epoch || v > epoch+uint64(400*365*24*3600)*10_000_000 {
		return time.Time{}
	}
	return time.Unix(0, int64(v-epoch)*100).UTC()
}

func utf16s(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func utf16z(b []byte) string {
	s := utf16s(b)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return latin1(b[:i])
		}
	}
	return latin1(b)
}
