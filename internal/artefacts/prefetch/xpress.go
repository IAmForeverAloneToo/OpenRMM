package prefetch

import "encoding/binary"

// decompressHuffman decodes LZXPRESS Huffman data (MS-XCA 2.2.4), the
// compression of Windows 10 and later prefetch files, into exactly size
// bytes. Every read is checked; damaged input returns ErrCorrupt.
func decompressHuffman(in []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	pos := 0
	var lengths [512]uint8
	table := make([]uint16, 1<<15)
	// Bits past the end of the input read as zero: the decoder looks ahead
	// up to 32 bits.
	read16 := func() uint32 {
		var v uint32
		if pos+1 < len(in) {
			v = uint32(in[pos]) | uint32(in[pos+1])<<8
		}
		pos += 2
		return v
	}
	for len(out) < size {
		// Each block starts with the 4-bit code lengths of 512 symbols.
		if pos+256 > len(in) {
			return nil, ErrCorrupt
		}
		for i, b := range in[pos : pos+256] {
			lengths[2*i], lengths[2*i+1] = b&15, b>>4
		}
		if !buildTable(table, &lengths) {
			return nil, ErrCorrupt
		}
		pos += 256
		next := read16()<<16 | read16()
		extra := 16
		end := min(len(out)+65536, size)
		for len(out) < end {
			if pos > len(in)+4 {
				return nil, ErrCorrupt
			}
			sym := table[next>>17]
			n := int(lengths[sym])
			next <<= n
			if extra -= n; extra < 0 {
				next |= read16() << -extra
				extra += 16
			}
			if sym < 256 {
				out = append(out, byte(sym))
				continue
			}
			sym -= 256
			length, bits := int(sym&15), int(sym>>4)
			if length == 15 {
				if pos >= len(in) {
					return nil, ErrCorrupt
				}
				length = int(in[pos])
				pos++
				if length == 255 {
					if pos+2 > len(in) {
						return nil, ErrCorrupt
					}
					length = int(in[pos]) | int(in[pos+1])<<8
					pos += 2
					// A zero 16-bit length is followed by a 32-bit one.
					if length == 0 {
						if pos+4 > len(in) {
							return nil, ErrCorrupt
						}
						length = int(binary.LittleEndian.Uint32(in[pos:]))
						pos += 4
					}
					if length < 15 || length > size {
						return nil, ErrCorrupt
					}
					length -= 15
				}
				length += 15
			}
			length += 3
			offset := int(next>>(32-bits)) + 1<<bits
			next <<= bits
			if extra -= bits; extra < 0 {
				next |= read16() << -extra
				extra += 16
			}
			if offset > len(out) {
				return nil, ErrCorrupt
			}
			for i := 0; i < length && len(out) < size; i++ {
				out = append(out, out[len(out)-offset])
			}
		}
	}
	return out, nil
}

// buildTable fills a 15-bit lookup table from canonical Huffman code
// lengths; the lengths must describe a complete code.
func buildTable(t []uint16, lengths *[512]uint8) bool {
	i := 0
	for n := uint8(1); n <= 15; n++ {
		for s, l := range lengths {
			if l != n {
				continue
			}
			c := 1 << (15 - n)
			if i+c > len(t) {
				return false
			}
			for k := range c {
				t[i+k] = uint16(s)
			}
			i += c
		}
	}
	return i == len(t)
}
