package registry

import (
	"math/bits"
	"slices"
)

// Transaction logs of Windows 8.1 and later hold log entries ("HvLE"),
// each a set of dirty pages of the hive with a sequence number and two
// Marvin32 hashes. Entries continuing the hive's sequence are applied in
// order; the older log format (before Windows 8.1) is not replayed.

type page struct {
	offset uint32
	data   []byte
}

type logEntry struct {
	seq      uint32
	binsSize uint32
	pages    []page
}

// replay applies the logs' entries to a dirty hive and returns the hive
// and the number of entries applied.
func replay(b []byte, logs [][]byte) ([]byte, int) {
	var entries []logEntry
	for _, l := range logs {
		entries = append(entries, logEntries(l)...)
	}
	slices.SortStableFunc(entries, func(a, b logEntry) int {
		switch {
		case a.seq < b.seq:
			return -1
		case a.seq > b.seq:
			return 1
		}
		return 0
	})
	// Entries from the hive's last complete write on, without gaps; both
	// logs may hold the same entry.
	next := le.Uint32(b[8:])
	applied := 0
	for _, e := range entries {
		if e.seq < next {
			continue
		}
		if applied > 0 && e.seq != next {
			break
		}
		need := baseBlock + int(e.binsSize)
		if need > MaxHive {
			break
		}
		if len(b) < need {
			b = append(b, make([]byte, need-len(b))...)
		}
		for _, p := range e.pages {
			if o := baseBlock + int(p.offset); o+len(p.data) <= len(b) {
				copy(b[o:], p.data)
			}
		}
		le.PutUint32(b[40:], e.binsSize)
		next, applied = e.seq+1, applied+1
	}
	if applied > 0 {
		le.PutUint32(b[4:], next)
		le.PutUint32(b[8:], next)
		le.PutUint32(b[508:], checksum(b))
	}
	return b, applied
}

// logEntries reads a log's valid entries: from the first, while their
// signatures, sizes, hashes and sequence numbers check.
func logEntries(l []byte) []logEntry {
	if len(l) < 512 || string(l[:4]) != "regf" {
		return nil
	}
	var out []logEntry
	for pos := 512; pos+40 <= len(l); {
		e := l[pos:]
		size := int(le.Uint32(e[4:]))
		if string(e[:4]) != "HvLE" || size < 40 || size%512 != 0 || size > len(e) {
			break
		}
		e = e[:size]
		if marvin32(e[40:]) != le.Uint64(e[24:]) || marvin32(e[:32]) != le.Uint64(e[32:]) {
			break
		}
		seq := le.Uint32(e[12:])
		if len(out) > 0 && seq != out[len(out)-1].seq+1 {
			break
		}
		entry := logEntry{seq: seq, binsSize: le.Uint32(e[16:])}
		count := int(le.Uint32(e[20:]))
		data := 40 + 8*count
		if count > size/8 || data > size {
			break
		}
		ok := true
		for i := range count {
			r := e[40+8*i:]
			off, n := le.Uint32(r), int(le.Uint32(r[4:]))
			if n < 0 || n > size-data || off%4096 != 0 {
				ok = false
				break
			}
			entry.pages = append(entry.pages, page{off, e[data : data+n]})
			data += n
		}
		if !ok {
			break
		}
		out = append(out, entry)
		pos += size
	}
	return out
}

// marvin32 is the Marvin32 hash with the registry's seed.
func marvin32(b []byte) uint64 {
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
