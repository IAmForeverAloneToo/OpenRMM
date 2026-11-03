// Package registrytest builds registry hives and transaction logs for tests.
package registrytest

import (
	"encoding/binary"
	"math/bits"
	"time"
	"unicode/utf16"
)

var le = binary.LittleEndian

// Key is a key to build, with its values and subkeys.
type Key struct {
	Name    string
	Time    time.Time
	Values  []Value
	Subkeys []*Key
}

// Value is a value to build.
type Value struct {
	Name string
	Type uint32
	Data []byte
}

// FT converts a time to a FILETIME.
func FT(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

// U16 encodes UTF-16LE text with a terminating NUL.
func U16(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = le.AppendUint16(b, c)
	}
	return append(b, 0, 0)
}

// DWord encodes a REG_DWORD.
func DWord(v uint32) []byte { return le.AppendUint32(nil, v) }

type builder struct{ bins []byte }

func (b *builder) cell(data []byte) uint32 {
	off := uint32(len(b.bins))
	size := (4 + len(data) + 7) &^ 7
	c := make([]byte, size)
	le.PutUint32(c, uint32(-int32(size)))
	copy(c[4:], data)
	b.bins = append(b.bins, c...)
	return off
}

func (b *builder) value(v Value) uint32 {
	name := []byte(v.Name)
	d := make([]byte, 20)
	copy(d, "vk")
	le.PutUint16(d[2:], uint16(len(name)))
	le.PutUint32(d[12:], v.Type)
	le.PutUint16(d[16:], 1) // ASCII name
	switch {
	case len(v.Data) <= 4:
		le.PutUint32(d[4:], uint32(len(v.Data))|0x80000000)
		copy(d[8:], v.Data)
	case len(v.Data) > 16344:
		var segs []byte
		for rest := v.Data; len(rest) > 0; {
			n := min(len(rest), 16344)
			segs = le.AppendUint32(segs, b.cell(rest[:n]))
			rest = rest[n:]
		}
		list := b.cell(segs)
		db := make([]byte, 8)
		copy(db, "db")
		le.PutUint16(db[2:], uint16(len(segs)/4))
		le.PutUint32(db[4:], list)
		le.PutUint32(d[4:], uint32(len(v.Data)))
		le.PutUint32(d[8:], b.cell(db))
	default:
		le.PutUint32(d[4:], uint32(len(v.Data)))
		le.PutUint32(d[8:], b.cell(v.Data))
	}
	return b.cell(append(d, name...))
}

// key builds a key; at, when not zero, is a cell reserved for it.
func (b *builder) key(k *Key, at uint32) uint32 {
	var subs []uint32
	for _, s := range k.Subkeys {
		subs = append(subs, b.key(s, 0))
	}
	d := make([]byte, 76)
	copy(d, "nk")
	le.PutUint16(d[2:], 0x20) // ASCII name
	le.PutUint64(d[4:], FT(k.Time))
	le.PutUint32(d[20:], uint32(len(subs)))
	le.PutUint32(d[28:], 0xFFFFFFFF)
	le.PutUint32(d[40:], 0xFFFFFFFF)
	if len(subs) > 0 {
		list := []byte("lf")
		list = le.AppendUint16(list, uint16(len(subs)))
		for _, s := range subs {
			list = le.AppendUint32(list, s)
			list = append(list, 0, 0, 0, 0)
		}
		le.PutUint32(d[28:], b.cell(list))
	}
	if len(k.Values) > 0 {
		var list []byte
		for _, v := range k.Values {
			list = le.AppendUint32(list, b.value(v))
		}
		le.PutUint32(d[36:], uint32(len(k.Values)))
		le.PutUint32(d[40:], b.cell(list))
	}
	le.PutUint16(d[72:], uint16(len(k.Name)))
	d = append(d, k.Name...)
	if at != 0 {
		copy(b.bins[at+4:], d)
		return at
	}
	return b.cell(d)
}

// Hive builds a clean hive (sequence numbers equal) with root as its root
// key, written at time at.
func Hive(root *Key, at time.Time) []byte {
	// The root key comes first, so it keeps its place in later versions.
	b := &builder{bins: make([]byte, 32)}
	off := b.key(root, b.cell(make([]byte, 76+len(root.Name))))
	size := (len(b.bins) + 4095) &^ 4095
	b.bins = append(b.bins, make([]byte, size-len(b.bins))...)
	copy(b.bins, "hbin")
	le.PutUint32(b.bins[8:], uint32(size))
	h := make([]byte, 4096, 4096+size)
	copy(h, "regf")
	le.PutUint32(h[4:], 5)
	le.PutUint32(h[8:], 5)
	le.PutUint64(h[12:], FT(at))
	le.PutUint32(h[20:], 1)
	le.PutUint32(h[24:], 6)
	le.PutUint32(h[32:], 1)
	le.PutUint32(h[36:], off)
	le.PutUint32(h[40:], uint32(size))
	le.PutUint32(h[44:], 1)
	SetChecksum(h)
	return append(h, b.bins...)
}

// SetChecksum recomputes a base block's checksum.
func SetChecksum(h []byte) {
	var x uint32
	for i := 0; i < 508; i += 4 {
		x ^= le.Uint32(h[i:])
	}
	le.PutUint32(h[508:], x)
}

// Log builds a transaction log with one entry of sequence number seq that
// turns old's hive bins into new's: every differing 4 KiB page.
func Log(old, new []byte, seq uint32) []byte {
	l := make([]byte, 512)
	copy(l, new[:512])
	le.PutUint32(l[28:], 6)
	SetChecksum(l)
	var refs, data []byte
	count := 0
	for off := 4096; off < len(new); off += 4096 {
		end := min(off+4096, len(new))
		if off < len(old) && string(old[off:min(end, len(old))]) == string(new[off:end]) && end <= len(old) {
			continue
		}
		refs = le.AppendUint32(refs, uint32(off-4096))
		refs = le.AppendUint32(refs, uint32(end-off))
		data = append(data, new[off:end]...)
		count++
	}
	e := make([]byte, 40)
	copy(e, "HvLE")
	le.PutUint32(e[12:], seq)
	le.PutUint32(e[16:], le.Uint32(new[40:]))
	le.PutUint32(e[20:], uint32(count))
	e = append(append(e, refs...), data...)
	e = append(e, make([]byte, (512-len(e)%512)%512)...)
	le.PutUint32(e[4:], uint32(len(e)))
	le.PutUint64(e[24:], Marvin32(e[40:]))
	le.PutUint64(e[32:], Marvin32(e[:32]))
	return append(l, e...)
}

// Marvin32 hashes with the registry's seed.
func Marvin32(b []byte) uint64 {
	const seed = 0x82EF4D887A4E55C5
	p0, p1 := uint32(seed&0xFFFFFFFF), uint32(seed>>32)
	block := func() {
		p1 ^= p0
		p0 = bits.RotateLeft32(p0, 20)
		p0 += p1
		p1 = bits.RotateLeft32(p1, 9)
		p1 ^= p0
		p0 = bits.RotateLeft32(p0, 27)
		p0 += p1
		p1 = bits.RotateLeft32(p1, 19)
	}
	for len(b) >= 4 {
		p0 += le.Uint32(b)
		block()
		b = b[4:]
	}
	switch len(b) {
	case 0:
		p0 += 0x80
	case 1:
		p0 += 0x8000 | uint32(b[0])
	case 2:
		p0 += 0x800000 | uint32(le.Uint16(b))
	case 3:
		p0 += 0x80000000 | uint32(b[2])<<16 | uint32(le.Uint16(b))
	}
	block()
	block()
	return uint64(p1)<<32 | uint64(p0)
}
