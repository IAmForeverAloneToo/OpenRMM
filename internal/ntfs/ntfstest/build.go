// Package ntfstest builds small synthetic NTFS volumes for tests: 512-byte
// sectors, 4 KiB clusters, 1 KiB records.
package ntfstest

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

const (
	Sector     = 512
	Cluster    = 4096
	RecordSize = 1024
)

var Time = time.Date(2026, 10, 30, 12, 0, 0, 1234500, time.UTC)

func ft(t time.Time) uint64 { return uint64(t.UnixNano()/100) + 116444736000000000 }

func u16s(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func pad8(b []byte) []byte {
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

// resident builds a resident attribute.
func resident(typ uint32, name string, value []byte) []byte {
	n := u16s(name)
	hdr := 0x18
	voff := (hdr + len(n) + 7) &^ 7
	a := make([]byte, voff)
	binary.LittleEndian.PutUint32(a, typ)
	a[9] = byte(len(n) / 2)
	binary.LittleEndian.PutUint16(a[10:], uint16(hdr))
	copy(a[hdr:], n)
	binary.LittleEndian.PutUint32(a[16:], uint32(len(value)))
	binary.LittleEndian.PutUint16(a[20:], uint16(voff))
	a = pad8(append(a, value...))
	binary.LittleEndian.PutUint32(a[4:], uint32(len(a)))
	return a
}

type tRun struct {
	lcn, length int64
	sparse      bool
}

func encodeRuns(runs []tRun) []byte {
	var b []byte
	var prev int64
	for _, r := range runs {
		l := make([]byte, 8)
		binary.LittleEndian.PutUint64(l, uint64(r.length))
		ls := 8
		for ls > 1 && l[ls-1] == 0 {
			ls--
		}
		if r.sparse {
			b = append(append(b, byte(ls)), l[:ls]...)
			continue
		}
		d := r.lcn - prev
		prev = r.lcn
		o := make([]byte, 8)
		binary.LittleEndian.PutUint64(o, uint64(d))
		os := 8
		for os > 1 && (o[os-1] == 0 && o[os-2]&0x80 == 0 || o[os-1] == 0xFF && o[os-2]&0x80 != 0) {
			os--
		}
		b = append(append(append(b, byte(ls|os<<4)), l[:ls]...), o[:os]...)
	}
	return append(b, 0)
}

// nonResident builds a non-resident attribute fragment.
func nonResident(typ uint32, name string, startVCN, size int64, runs []tRun, flags uint16) []byte {
	n := u16s(name)
	hdr := 0x40
	roff := (hdr + len(n) + 7) &^ 7
	a := make([]byte, roff)
	binary.LittleEndian.PutUint32(a, typ)
	a[8] = 1
	a[9] = byte(len(n) / 2)
	binary.LittleEndian.PutUint16(a[10:], uint16(hdr))
	binary.LittleEndian.PutUint16(a[12:], flags)
	copy(a[hdr:], n)
	var clusters int64
	for _, r := range runs {
		clusters += r.length
	}
	binary.LittleEndian.PutUint64(a[0x10:], uint64(startVCN))
	binary.LittleEndian.PutUint64(a[0x18:], uint64(startVCN+clusters-1))
	binary.LittleEndian.PutUint16(a[0x20:], uint16(roff))
	binary.LittleEndian.PutUint64(a[0x28:], uint64(size))
	binary.LittleEndian.PutUint64(a[0x30:], uint64(size))
	binary.LittleEndian.PutUint64(a[0x38:], uint64(size))
	a = pad8(append(a, encodeRuns(runs)...))
	binary.LittleEndian.PutUint32(a[4:], uint32(len(a)))
	return a
}

func si(t time.Time, flags uint32, usn uint64) []byte {
	v := make([]byte, 0x48)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(v[8*i:], ft(t.Add(time.Duration(i)*time.Hour)))
	}
	binary.LittleEndian.PutUint32(v[0x20:], flags)
	binary.LittleEndian.PutUint64(v[0x40:], usn)
	return resident(0x10, "", v)
}

func fn(parent uint64, pseq uint16, name string, ns uint8, size uint64, t time.Time) []byte {
	n := u16s(name)
	v := make([]byte, 0x42+len(n))
	binary.LittleEndian.PutUint64(v, parent|uint64(pseq)<<48)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(v[8+8*i:], ft(t))
	}
	binary.LittleEndian.PutUint64(v[0x30:], size)
	v[0x40] = byte(len(n) / 2)
	v[0x41] = ns
	copy(v[0x42:], n)
	return resident(0x30, "", v)
}

func listEntry(typ uint32, name string, vcn int64, rec uint64, seq uint16) []byte {
	n := u16s(name)
	e := make([]byte, 0x1A)
	binary.LittleEndian.PutUint32(e, typ)
	e[6], e[7] = byte(len(n)/2), 0x1A
	binary.LittleEndian.PutUint64(e[8:], uint64(vcn))
	binary.LittleEndian.PutUint64(e[0x10:], rec|uint64(seq)<<48)
	e = pad8(append(e, n...))
	binary.LittleEndian.PutUint16(e[4:], uint16(len(e)))
	return e
}

// record builds a FILE record with fixups applied as on disk.
func record(seq uint16, flags uint16, base uint64, attrs ...[]byte) []byte {
	b := make([]byte, RecordSize)
	copy(b, "FILE")
	binary.LittleEndian.PutUint16(b[4:], 0x30)
	binary.LittleEndian.PutUint16(b[6:], RecordSize/Sector+1)
	binary.LittleEndian.PutUint64(b[8:], 777)
	binary.LittleEndian.PutUint16(b[0x10:], seq)
	binary.LittleEndian.PutUint16(b[0x14:], 0x38)
	binary.LittleEndian.PutUint16(b[0x16:], flags)
	binary.LittleEndian.PutUint64(b[0x20:], base)
	pos := 0x38
	for _, a := range attrs {
		copy(b[pos:], a)
		pos += len(a)
	}
	binary.LittleEndian.PutUint32(b[pos:], 0xFFFFFFFF)
	pos += 8
	binary.LittleEndian.PutUint32(b[0x18:], uint32(pos))
	binary.LittleEndian.PutUint32(b[0x1C:], RecordSize)
	// Update sequence: number 0x0042; each sector's last two bytes move to
	// the array.
	binary.LittleEndian.PutUint16(b[0x30:], 0x42)
	for i := 1; i <= RecordSize/Sector; i++ {
		end := i*Sector - 2
		copy(b[0x30+2*i:], b[end:end+2])
		binary.LittleEndian.PutUint16(b[end:], 0x42)
	}
	return b
}

// USNV2 builds a version 2 change journal record.
func USNV2(file, parent uint64, usn int64, reason uint32, name string) []byte {
	n := u16s(name)
	b := make([]byte, 60)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint64(b[8:], file|1<<48)
	binary.LittleEndian.PutUint64(b[16:], parent|1<<48)
	binary.LittleEndian.PutUint64(b[24:], uint64(usn))
	binary.LittleEndian.PutUint64(b[32:], ft(Time))
	binary.LittleEndian.PutUint32(b[40:], reason)
	binary.LittleEndian.PutUint32(b[52:], 0x20)
	binary.LittleEndian.PutUint16(b[56:], uint16(len(n)))
	binary.LittleEndian.PutUint16(b[58:], 60)
	b = pad8(append(b, n...))
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

// USNV3 builds a version 3 change journal record.
func USNV3(file, parent uint64, usn int64, reason uint32, name string) []byte {
	n := u16s(name)
	b := make([]byte, 76)
	binary.LittleEndian.PutUint16(b[4:], 3)
	binary.LittleEndian.PutUint64(b[8:], file|2<<48)
	binary.LittleEndian.PutUint64(b[24:], parent|1<<48)
	binary.LittleEndian.PutUint64(b[40:], uint64(usn))
	binary.LittleEndian.PutUint64(b[48:], ft(Time))
	binary.LittleEndian.PutUint32(b[56:], reason)
	binary.LittleEndian.PutUint16(b[72:], uint16(len(n)))
	binary.LittleEndian.PutUint16(b[74:], 76)
	b = pad8(append(b, n...))
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

// Volume returns a 1 MiB volume: the MFT is split in two runs (clusters 4-7
// and 40-43, 32 records); record 0's second fragment is in extension record
// 15 through an attribute list. Record 5 is the root, 11 is $Extend, 20 is
// a directory "Users", 21 a file "a.txt" with an alternate stream and a
// hard link "Link to a.txt" in the root (with a DOS short name), 22 a
// deleted file whose directory was reused, 23 "$UsnJrnl" with a sparse $J.
func Volume() ([]byte, []byte) {
	vol := make([]byte, 256*Cluster)
	boot := vol[:512]
	copy(boot[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(boot[0x0B:], Sector)
	boot[0x0D] = Cluster / Sector
	binary.LittleEndian.PutUint64(boot[0x30:], 4)
	boot[0x40] = 0xF6 // 2^10 = 1024-byte records
	binary.LittleEndian.PutUint64(boot[0x48:], 0x1234)
	mftSize := int64(32 * RecordSize)
	records := map[uint64][]byte{
		0: record(1, 1, 0,
			si(Time, 6, 0),
			resident(0x20, "", append(listEntry(0x80, "", 0, 0, 1), listEntry(0x80, "", 4, 15, 1)...)),
			fn(5, 5, "$MFT", 3, uint64(mftSize), Time),
			nonResident(0x80, "", 0, mftSize, []tRun{{lcn: 4, length: 4}}, 0)),
		15: record(1, 1, 0|1<<48, nonResident(0x80, "", 4, 0, []tRun{{lcn: 40, length: 4}}, 0)),
		5:  record(5, 3, 0, si(Time, 6, 0), fn(5, 5, ".", 1, 0, Time)),
		11: record(11, 3, 0, fn(5, 5, "$Extend", 3, 0, Time)),
		20: record(1, 3, 0, si(Time, 0x10, 0), fn(5, 5, "Users", 1, 0, Time), fn(5, 5, "USERS~1", 2, 0, Time)),
		21: record(1, 1, 0, si(Time, 0x20, 99), fn(20, 1, "a.txt", 3, 5, Time), fn(5, 5, "Link to a.txt", 1, 5, Time), fn(5, 5, "LINKTO~1.TXT", 2, 5, Time), resident(0x80, "", []byte("hello")), resident(0x80, "Zone.Identifier", []byte("[ZoneTransfer]"))),
		22: record(2, 0, 0, si(Time, 0x20, 0), fn(20, 7, "gone.exe", 1, 0, Time)),
		23: record(1, 1, 0, fn(11, 11, "$UsnJrnl", 3, 0, Time), nonResident(0x80, "$J", 0, 3*Cluster, []tRun{{length: 2, sparse: true}, {lcn: 60, length: 1}}, 0x8000)),
	}
	for n, r := range records {
		off := int64(n) * RecordSize
		lcn := int64(4)
		if off >= 4*Cluster {
			lcn, off = 40, off-4*Cluster
		}
		copy(vol[lcn*Cluster+off:], r)
	}
	journal := append(append(USNV2(21, 20, 4096*2, 0x100, "a.txt"), make([]byte, 24)...), USNV3(22, 20, 4096*2+88, 0x200|0x80000000, "gone.exe")...)
	copy(vol[60*Cluster:], journal)
	return vol, journal
}
