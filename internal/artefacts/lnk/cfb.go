package lnk

import "errors"

// An OLE compound file (MS-CFB) reader, enough for jump lists: the
// directory's streams and their contents through the FAT or, for small
// streams, the mini FAT. Chains are bounded so a crafted file cannot loop.

var errCFB = errors.New("lnk: damaged compound file")

const (
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
)

type cfb struct {
	b          []byte
	shift      uint
	fat        []uint32
	miniFAT    []uint32
	mini       []byte
	cutoff     uint64
	dir        []byte
	miniSector int
}

type stream struct {
	name  string
	start uint32
	size  uint64
}

func openCFB(b []byte) (*cfb, error) {
	if len(b) < 512 || string(b[:8]) != "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" {
		return nil, errCFB
	}
	f := &cfb{b: b, shift: uint(le.Uint16(b[30:])), cutoff: uint64(le.Uint32(b[56:])), miniSector: 1 << le.Uint16(b[32:])}
	if f.shift != 9 && f.shift != 12 || f.miniSector != 64 {
		return nil, errCFB
	}
	// The FAT's sectors: 109 in the header, more in DIFAT sectors.
	var fatSectors []uint32
	for i := range 109 {
		if s := le.Uint32(b[76+4*i:]); s != freeSect {
			fatSectors = append(fatSectors, s)
		}
	}
	per := (1 << f.shift) / 4
	next := le.Uint32(b[68:])
	for n := 0; next != endOfChain && next != freeSect && n < 1<<16; n++ {
		d, err := f.sector(next)
		if err != nil {
			return nil, err
		}
		for i := 0; i < per-1; i++ {
			if s := le.Uint32(d[4*i:]); s != freeSect {
				fatSectors = append(fatSectors, s)
			}
		}
		next = le.Uint32(d[4*(per-1):])
	}
	for _, s := range fatSectors {
		d, err := f.sector(s)
		if err != nil {
			return nil, err
		}
		for i := 0; i < per; i++ {
			f.fat = append(f.fat, le.Uint32(d[4*i:]))
		}
	}
	var err error
	if f.dir, err = f.chain(le.Uint32(b[48:]), 0); err != nil {
		return nil, err
	}
	if mf, err := f.chain(le.Uint32(b[60:]), 0); err == nil {
		for i := 0; i+4 <= len(mf); i += 4 {
			f.miniFAT = append(f.miniFAT, le.Uint32(mf[i:]))
		}
	}
	// The root entry's stream is the mini stream.
	if len(f.dir) >= 128 {
		root := f.dir[:128]
		f.mini, _ = f.chain(le.Uint32(root[116:]), le.Uint64(root[120:]))
	}
	return f, nil
}

func (f *cfb) sector(n uint32) ([]byte, error) {
	size := 1 << f.shift
	off := (int(n) + 1) * size
	if n >= endOfChain-1 || off+size > len(f.b) {
		return nil, errCFB
	}
	return f.b[off : off+size], nil
}

// chain reads a sector chain, up to size bytes when size is set.
func (f *cfb) chain(start uint32, size uint64) ([]byte, error) {
	var out []byte
	for n, s := 0, start; s != endOfChain; n++ {
		// A chain longer than the FAT loops.
		if n > len(f.fat) {
			return nil, errCFB
		}
		d, err := f.sector(s)
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
		if size > 0 && uint64(len(out)) >= size {
			return out[:size], nil
		}
		if int(s) >= len(f.fat) {
			return nil, errCFB
		}
		s = f.fat[s]
	}
	if size > 0 && uint64(len(out)) < size {
		return nil, errCFB
	}
	return out, nil
}

// streams lists the directory's stream entries.
func (f *cfb) streams() []stream {
	var out []stream
	for i := 0; i+128 <= len(f.dir); i += 128 {
		e := f.dir[i : i+128]
		if e[66] != 2 {
			continue
		}
		n := int(le.Uint16(e[64:]))
		if n < 2 || n > 64 {
			continue
		}
		size := le.Uint64(e[120:])
		if le.Uint16(f.b[26:]) == 3 {
			size &= 0xFFFFFFFF
		}
		out = append(out, stream{name: utf16s(e[:n-2]), start: le.Uint32(e[116:]), size: size})
	}
	return out
}

// read returns a stream's contents.
func (f *cfb) read(s stream) ([]byte, error) {
	if s.size > MaxFile {
		return nil, errCFB
	}
	if s.size == 0 {
		return nil, nil
	}
	if s.size >= f.cutoff {
		return f.chain(s.start, s.size)
	}
	var out []byte
	for n, m := 0, s.start; m != endOfChain && uint64(len(out)) < s.size; n++ {
		off := int(m) * f.miniSector
		if n > len(f.miniFAT) || int(m) >= len(f.miniFAT) || off+f.miniSector > len(f.mini) {
			return nil, errCFB
		}
		out = append(out, f.mini[off:off+f.miniSector]...)
		m = f.miniFAT[m]
	}
	if uint64(len(out)) < s.size {
		return nil, errCFB
	}
	return out[:s.size], nil
}
