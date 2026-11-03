// Package prefetch reads Windows prefetch files (.pf): the program, how
// often and when it last ran, the volumes it used and the files it loaded.
// Versions 17 (XP), 23 (Vista, 7), 26 (8.1) and 30 and 31 (10, 11, also
// compressed) are read. It uses only the standard library; every offset and
// length is checked before use.
package prefetch

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf16"
)

// ErrCorrupt reports a file that does not decode.
var ErrCorrupt = errors.New("prefetch: corrupt or unsupported file")

// Limits on what is decoded, far above real prefetch files.
const (
	MaxFile     = 16 << 20
	maxExpanded = 64 << 20
	maxFiles    = 100_000
)

// Volume is a volume a program used.
type Volume struct {
	Device  string
	Serial  uint32
	Created time.Time
}

// Info is a decoded prefetch file.
type Info struct {
	Version    int
	Executable string
	Hash       uint32
	RunCount   uint32
	// Runs are the last run times, newest first (one before version 26,
	// up to eight after).
	Runs    []time.Time
	Volumes []Volume
	Files   []string
}

// Path returns the loaded file that is the program itself, or "".
func (i Info) Path() string {
	for _, f := range i.Files {
		if n := strings.LastIndexByte(f, '\\'); n >= 0 && strings.EqualFold(f[n+1:], i.Executable) {
			return f
		}
	}
	return ""
}

// Parse decodes a prefetch file, decompressing it first if needed.
func Parse(b []byte) (Info, error) {
	if len(b) > MaxFile {
		return Info{}, ErrCorrupt
	}
	if len(b) >= 8 && string(b[:3]) == "MAM" {
		// MAM: byte 3 is the compression format (4, XPRESS Huffman), with
		// 0x80 set when a checksum follows the expanded size.
		if b[3]&0x7F != 4 {
			return Info{}, ErrCorrupt
		}
		size := int(binary.LittleEndian.Uint32(b[4:]))
		data := b[8:]
		if b[3]&0x80 != 0 {
			if len(data) < 4 {
				return Info{}, ErrCorrupt
			}
			data = data[4:]
		}
		if size < 84 || size > maxExpanded {
			return Info{}, ErrCorrupt
		}
		var err error
		if b, err = decompressHuffman(data, size); err != nil {
			return Info{}, err
		}
	}
	return parse(b)
}

func parse(b []byte) (Info, error) {
	if len(b) < 84 || string(b[4:8]) != "SCCA" {
		return Info{}, ErrCorrupt
	}
	le := binary.LittleEndian
	i := Info{Version: int(le.Uint32(b)), Executable: utf16z(b[16:76]), Hash: le.Uint32(b[76:])}
	var runs, count int
	switch i.Version {
	case 17:
		runs, count = 120, 144
	case 23:
		runs, count = 128, 152
	case 26:
		runs, count = 128, 208
	case 30, 31:
		// Two layouts: the run count follows 16 or 8 unknown bytes, told
		// apart by where the metrics array starts.
		runs, count = 128, 208
		if len(b) >= 88 && le.Uint32(b[84:]) == 0x128 {
			count = 200
		}
	default:
		return Info{}, ErrCorrupt
	}
	if len(b) < count+4 {
		return Info{}, ErrCorrupt
	}
	i.RunCount = le.Uint32(b[count:])
	n := 1
	if i.Version >= 26 {
		n = 8
	}
	for k := range n {
		if t := filetime(le.Uint64(b[runs+8*k:])); !t.IsZero() {
			i.Runs = append(i.Runs, t)
		}
	}
	// Loaded files: consecutive NUL-terminated UTF-16 strings.
	if off, size, ok := span(b, le.Uint32(b[100:]), le.Uint32(b[104:])); ok {
		for _, s := range strings.Split(utf16s(b[off:off+size]), "\x00") {
			if s != "" && len(i.Files) < maxFiles {
				i.Files = append(i.Files, s)
			}
		}
	}
	// Volumes: entries of 40 (version 17), 104 (23, 26) or 96 bytes
	// (30, 31), each naming its device path relative to the volume area.
	entry := 104
	switch {
	case i.Version == 17:
		entry = 40
	case i.Version >= 30:
		entry = 96
	}
	if off, size, ok := span(b, le.Uint32(b[108:]), le.Uint32(b[116:])); ok {
		area := b[off : off+size]
		vols := int(le.Uint32(b[112:]))
		for k := 0; k < vols && k < 64 && (k+1)*entry <= len(area); k++ {
			e := area[k*entry:]
			v := Volume{Created: filetime(le.Uint64(e[8:])), Serial: le.Uint32(e[16:])}
			if p, l := int(le.Uint32(e)), int(le.Uint32(e[4:])); p >= 0 && l > 0 && l < 1024 && p+2*l <= len(area) {
				v.Device = utf16s(area[p : p+2*l])
			}
			i.Volumes = append(i.Volumes, v)
		}
	}
	return i, nil
}

// span checks an offset and size within b.
func span(b []byte, off, size uint32) (int, int, bool) {
	o, s := int(off), int(size)
	return o, s, off != 0 && size != 0 && o <= len(b) && s <= len(b)-o
}

func utf16s(b []byte) string {
	u := make([]uint16, len(b)/2)
	for k := range u {
		u[k] = binary.LittleEndian.Uint16(b[2*k:])
	}
	return string(utf16.Decode(u))
}

// utf16z decodes up to the first NUL.
func utf16z(b []byte) string {
	s := utf16s(b)
	if n := strings.IndexByte(s, 0); n >= 0 {
		s = s[:n]
	}
	return s
}

// filetime converts a FILETIME; zero and out-of-range values are zero.
func filetime(v uint64) time.Time {
	const epoch = 116444736000000000 // 1601 to 1970 in 100 ns
	if v <= epoch || v > epoch+uint64(400*365*24*3600)*10_000_000 {
		return time.Time{}
	}
	return time.Unix(0, int64(v-epoch)*100).UTC()
}
