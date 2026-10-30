package ntfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// The tests build small synthetic volumes: 512-byte sectors, 4 KiB
// clusters, 1 KiB records.
const (
	tSector  = 512
	tCluster = 4096
	tRecord  = 1024
)

var tTime = time.Date(2026, 10, 30, 12, 0, 0, 1234500, time.UTC)

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
	return resident(attrStandardInformation, "", v)
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
	return resident(attrFileName, "", v)
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
	b := make([]byte, tRecord)
	copy(b, "FILE")
	binary.LittleEndian.PutUint16(b[4:], 0x30)
	binary.LittleEndian.PutUint16(b[6:], tRecord/tSector+1)
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
	binary.LittleEndian.PutUint32(b[pos:], attrEnd)
	pos += 8
	binary.LittleEndian.PutUint32(b[0x18:], uint32(pos))
	binary.LittleEndian.PutUint32(b[0x1C:], tRecord)
	// Update sequence: number 0x0042; each sector's last two bytes move to
	// the array.
	binary.LittleEndian.PutUint16(b[0x30:], 0x42)
	for i := 1; i <= tRecord/tSector; i++ {
		end := i*tSector - 2
		copy(b[0x30+2*i:], b[end:end+2])
		binary.LittleEndian.PutUint16(b[end:], 0x42)
	}
	return b
}

func usnV2(file, parent uint64, usn int64, reason uint32, name string) []byte {
	n := u16s(name)
	b := make([]byte, 60)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint64(b[8:], file|1<<48)
	binary.LittleEndian.PutUint64(b[16:], parent|1<<48)
	binary.LittleEndian.PutUint64(b[24:], uint64(usn))
	binary.LittleEndian.PutUint64(b[32:], ft(tTime))
	binary.LittleEndian.PutUint32(b[40:], reason)
	binary.LittleEndian.PutUint32(b[52:], 0x20)
	binary.LittleEndian.PutUint16(b[56:], uint16(len(n)))
	binary.LittleEndian.PutUint16(b[58:], 60)
	b = pad8(append(b, n...))
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

func usnV3(file, parent uint64, usn int64, reason uint32, name string) []byte {
	n := u16s(name)
	b := make([]byte, 76)
	binary.LittleEndian.PutUint16(b[4:], 3)
	binary.LittleEndian.PutUint64(b[8:], file|2<<48)
	binary.LittleEndian.PutUint64(b[24:], parent|1<<48)
	binary.LittleEndian.PutUint64(b[40:], uint64(usn))
	binary.LittleEndian.PutUint64(b[48:], ft(tTime))
	binary.LittleEndian.PutUint32(b[56:], reason)
	binary.LittleEndian.PutUint16(b[72:], uint16(len(n)))
	binary.LittleEndian.PutUint16(b[74:], 76)
	b = pad8(append(b, n...))
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

// testVolume is a 1 MiB volume: the MFT is split in two runs (clusters 4-7
// and 40-43, 32 records); record 0's second fragment is in extension record
// 15 through an attribute list. Record 5 is the root, 11 is $Extend, 20 is
// a directory "Users", 21 a file "a.txt" with an alternate stream, 22 a
// deleted file whose directory was reused, 23 "$UsnJrnl" with a sparse $J.
func testVolume(t *testing.T) ([]byte, []byte) {
	t.Helper()
	vol := make([]byte, 256*tCluster)
	boot := vol[:512]
	copy(boot[3:], "NTFS    ")
	binary.LittleEndian.PutUint16(boot[0x0B:], tSector)
	boot[0x0D] = tCluster / tSector
	binary.LittleEndian.PutUint64(boot[0x30:], 4)
	boot[0x40] = 0xF6 // 2^10 = 1024-byte records
	binary.LittleEndian.PutUint64(boot[0x48:], 0x1234)
	mftSize := int64(32 * tRecord)
	records := map[uint64][]byte{
		0: record(1, 1, 0,
			si(tTime, 6, 0),
			resident(attrAttributeList, "", append(listEntry(attrData, "", 0, 0, 1), listEntry(attrData, "", 4, 15, 1)...)),
			fn(5, 5, "$MFT", 3, uint64(mftSize), tTime),
			nonResident(attrData, "", 0, mftSize, []tRun{{lcn: 4, length: 4}}, 0)),
		15: record(1, 1, 0|1<<48, nonResident(attrData, "", 4, 0, []tRun{{lcn: 40, length: 4}}, 0)),
		5:  record(5, 3, 0, si(tTime, 6, 0), fn(5, 5, ".", 1, 0, tTime)),
		11: record(11, 3, 0, fn(5, 5, "$Extend", 3, 0, tTime)),
		20: record(1, 3, 0, si(tTime, 0x10, 0), fn(5, 5, "Users", 1, 0, tTime), fn(5, 5, "USERS~1", 2, 0, tTime)),
		21: record(1, 1, 0, si(tTime, 0x20, 99), fn(20, 1, "a.txt", 3, 5, tTime), resident(attrData, "", []byte("hello")), resident(attrData, "Zone.Identifier", []byte("[ZoneTransfer]"))),
		22: record(2, 0, 0, si(tTime, 0x20, 0), fn(20, 7, "gone.exe", 1, 0, tTime)),
		23: record(1, 1, 0, fn(11, 11, "$UsnJrnl", 3, 0, tTime), nonResident(attrData, "$J", 0, 3*tCluster, []tRun{{length: 2, sparse: true}, {lcn: 60, length: 1}}, 0x8000)),
	}
	for n, r := range records {
		off := int64(n) * tRecord
		lcn := int64(4)
		if off >= 4*tCluster {
			lcn, off = 40, off-4*tCluster
		}
		copy(vol[lcn*tCluster+off:], r)
	}
	journal := append(append(usnV2(21, 20, 4096*2, 0x100, "a.txt"), make([]byte, 24)...), usnV3(22, 20, 4096*2+88, 0x200|0x80000000, "gone.exe")...)
	copy(vol[60*tCluster:], journal)
	return vol, journal
}

func TestParseBoot(t *testing.T) {
	vol, _ := testVolume(t)
	b, err := ParseBoot(vol[:512])
	if err != nil || b.ClusterSize != tCluster || b.RecordSize != tRecord || b.MFTCluster != 4 || b.Serial != 0x1234 {
		t.Fatal(b, err)
	}
	bad := append([]byte(nil), vol[:512]...)
	copy(bad[3:], "EXFAT   ")
	if _, err := ParseBoot(bad); err != ErrNotNTFS {
		t.Fatal("not NTFS accepted")
	}
	bad = append([]byte(nil), vol[:512]...)
	bad[0x40] = 0x01 // one 4 KiB cluster per record is fine
	if b, err := ParseBoot(bad); err != nil || b.RecordSize != tCluster {
		t.Fatal(err)
	}
	bad[0x0B] = 7
	if _, err := ParseBoot(bad); err == nil {
		t.Fatal("odd sector size accepted")
	}
}

func TestRecordsStreamsAndPaths(t *testing.T) {
	vol, journal := testVolume(t)
	v, err := Open(bytes.NewReader(vol))
	if err != nil {
		t.Fatal(err)
	}
	if v.MFT().Size() != 32*tRecord {
		t.Fatal("MFT size", v.MFT().Size())
	}
	// Record 21 lies in the second MFT run, reached through the extension.
	r, err := v.Record(21)
	if err != nil || !r.InUse || r.Directory || len(r.Names) != 1 || r.Names[0].Name != "a.txt" || r.USN != 99 || r.SI.Modified != tTime.Add(time.Hour).Truncate(100) {
		t.Fatal(r, err)
	}
	if len(r.Streams) != 2 || string(r.Streams[0].Data) != "hello" || r.Streams[1].Name != "Zone.Identifier" {
		t.Fatal("streams", r.Streams)
	}
	users, _ := v.Record(20)
	if n, _ := users.Name(); n.Name != "Users" {
		t.Fatal("Win32 name not preferred over DOS", n.Name)
	}
	// A damaged sector ending (torn write) fails the fixup check.
	raw := make([]byte, tRecord)
	v.MFT().ReadAt(raw, 21*tRecord)
	raw[tSector-1] ^= 1
	if _, err := ParseRecord(raw, tSector, 21); err != ErrCorrupt {
		t.Fatal("torn record accepted")
	}
	// The sparse $J: the allocated part starts after two clusters.
	jr, _ := v.Record(23)
	j, err := v.OpenStream(jr, "$J")
	if err != nil || j.Size() != 3*tCluster || j.Allocated() != 2*tCluster {
		t.Fatal(err)
	}
	head := make([]byte, 16)
	if _, err := j.ReadAt(head, 0); err != nil || !bytes.Equal(head, make([]byte, 16)) {
		t.Fatal("hole not zero")
	}
	got := make([]byte, len(journal))
	if _, err := j.ReadAt(got, j.Allocated()); err != nil || !bytes.Equal(got, journal) {
		t.Fatal("journal data", err)
	}
	if _, err := j.ReadAt(make([]byte, 10), j.Size()-4); err != io.EOF {
		t.Fatal("read past the end", err)
	}
	// Timeline over a copy of the MFT.
	mft := make([]byte, v.MFT().Size())
	if _, err := v.MFT().ReadAt(mft, 0); err != nil {
		t.Fatal(err)
	}
	x := NewIndex()
	var rows [][]string
	var paths []string
	if err := ScanMFT(bytes.NewReader(mft), v.Boot, func(r Record, err error) error {
		if err == nil {
			x.Add(r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ScanMFT(bytes.NewReader(mft), v.Boot, func(r Record, err error) error {
		if row, p, ok := MFTRow(x, r, "C:"); ok && err == nil {
			rows, paths = append(rows, row), append(paths, p)
		}
		return nil
	})
	want := map[string]bool{`C:\$MFT`: true, `C:\.`: true, `C:\$Extend`: true, `C:\Users`: true, `C:\Users\a.txt`: true, `C:\<unknown>\gone.exe`: true, `C:\$Extend\$UsnJrnl`: true}
	if len(paths) != len(want) {
		t.Fatal(paths)
	}
	for _, p := range paths {
		if !want[p] {
			t.Fatal("unexpected path", p, paths)
		}
	}
	for _, row := range rows {
		if len(row) != len(MFTColumns) {
			t.Fatal("row width")
		}
		if row[6] == "a.txt" && (row[2] != "true" || row[8] != "5" || row[10] != "true" || row[7] != ".txt" || row[11] != "2026-10-30 12:00:00.0012345" || row[20] != "DosWindows") {
			t.Fatal("a.txt row", row)
		}
		if row[6] == "gone.exe" && row[2] != "false" {
			t.Fatal("deleted row", row)
		}
	}
	// Change journal entries resolve their parent directory.
	var usns [][]string
	if err := ScanUSN(bytes.NewReader(journal), 2*tCluster, func(u USNRecord) error {
		row, _ := USNRow(x, u, "C:")
		usns = append(usns, row)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(usns) != 2 || usns[0][6] != `C:\Users` || usns[0][9] != "FileCreate" || usns[1][9] != "FileDelete|Close" || usns[1][3] != "2" || usns[1][11] != "8288" || usns[1][7] != "8280" {
		t.Fatal("journal rows", usns)
	}
}

// Records are found across buffer boundaries, damage loses only the
// records it covers, and zero fill is skipped.
func TestScanUSNBoundariesAndDamage(t *testing.T) {
	var data []byte
	for len(data) < 1<<20-40 {
		data = append(data, usnV2(30, 5, int64(len(data)), 0x100, strings.Repeat("x", 9))...)
	}
	data = append(data, usnV3(31, 5, 1, 0x2, "boundary.txt")...) // crosses the 1 MiB read
	data = append(data, make([]byte, 4096)...)
	damaged := usnV2(32, 5, 2, 0x2, "damaged")
	binary.LittleEndian.PutUint16(damaged[4:], 9)
	data = append(data, damaged...)
	data = append(data, usnV2(33, 5, 3, 0x2, "after")...)
	var names []string
	if err := ScanUSN(bytes.NewReader(data), 0, func(u USNRecord) error { names = append(names, u.Name); return nil }); err != nil {
		t.Fatal(err)
	}
	if names[len(names)-2] != "boundary.txt" || names[len(names)-1] != "after" {
		t.Fatal("boundary or damage handling", names[len(names)-3:])
	}
	if ReasonBit("filedelete") != 0x200 || ReasonBit("nope") != 0 {
		t.Fatal("reason names")
	}
}

// Random input never panics.
func TestRandomInput(t *testing.T) {
	vol, _ := testVolume(t)
	rec := make([]byte, tRecord)
	copy(rec, vol[4*tCluster+21*tRecord:])
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), rec...)
		for j := 0; j < 1+rng.IntN(8); j++ {
			b[rng.IntN(len(b))] = byte(rng.Uint32())
		}
		ParseRecord(b, tSector, 21)
		parseUSN(b[rng.IntN(64):])
		decodeRuns(b, rng.IntN(len(b)))
	}
	for i := 0; i < 2000; i++ {
		b := append([]byte(nil), vol[:512]...)
		b[rng.IntN(512)] = byte(rng.Uint32())
		if boot, err := ParseBoot(b); err == nil {
			if v, err := Open(bytes.NewReader(append(b, vol[512:]...))); err == nil {
				v.Record(uint64(rng.IntN(40)))
			}
			_ = boot
		}
	}
}
