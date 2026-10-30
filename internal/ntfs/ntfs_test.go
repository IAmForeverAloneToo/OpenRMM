package ntfs

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/ntfs/ntfstest"
)

func TestParseBoot(t *testing.T) {
	vol, _ := ntfstest.Volume()
	b, err := ParseBoot(vol[:512])
	if err != nil || b.ClusterSize != ntfstest.Cluster || b.RecordSize != ntfstest.RecordSize || b.MFTCluster != 4 || b.Serial != 0x1234 {
		t.Fatal(b, err)
	}
	bad := append([]byte(nil), vol[:512]...)
	copy(bad[3:], "EXFAT   ")
	if _, err := ParseBoot(bad); err != ErrNotNTFS {
		t.Fatal("not NTFS accepted")
	}
	bad = append([]byte(nil), vol[:512]...)
	bad[0x40] = 0x01 // one 4 KiB cluster per record is fine
	if b, err := ParseBoot(bad); err != nil || b.RecordSize != ntfstest.Cluster {
		t.Fatal(err)
	}
	bad[0x0B] = 7
	if _, err := ParseBoot(bad); err == nil {
		t.Fatal("odd sector size accepted")
	}
}

func TestRecordsStreamsAndPaths(t *testing.T) {
	vol, journal := ntfstest.Volume()
	v, err := Open(bytes.NewReader(vol))
	if err != nil {
		t.Fatal(err)
	}
	if v.MFT().Size() != 32*ntfstest.RecordSize {
		t.Fatal("MFT size", v.MFT().Size())
	}
	// Record 21 lies in the second MFT run, reached through the extension.
	r, err := v.Record(21)
	if err != nil || !r.InUse || r.Directory || len(r.Names) != 1 || r.Names[0].Name != "a.txt" || r.USN != 99 || r.SI.Modified != ntfstest.Time.Add(time.Hour).Truncate(100) {
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
	raw := make([]byte, ntfstest.RecordSize)
	v.MFT().ReadAt(raw, 21*ntfstest.RecordSize)
	raw[ntfstest.Sector-1] ^= 1
	if _, err := ParseRecord(raw, ntfstest.Sector, 21); err != ErrCorrupt {
		t.Fatal("torn record accepted")
	}
	// The sparse $J: the allocated part starts after two clusters.
	jr, _ := v.Record(23)
	j, err := v.OpenStream(jr, "$J")
	if err != nil || j.Size() != 3*ntfstest.Cluster || j.Allocated() != 2*ntfstest.Cluster {
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
	if err := ScanUSN(bytes.NewReader(journal), 2*ntfstest.Cluster, func(u USNRecord) error {
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
		data = append(data, ntfstest.USNV2(30, 5, int64(len(data)), 0x100, strings.Repeat("x", 9))...)
	}
	data = append(data, ntfstest.USNV3(31, 5, 1, 0x2, "boundary.txt")...) // crosses the 1 MiB read
	data = append(data, make([]byte, 4096)...)
	damaged := ntfstest.USNV2(32, 5, 2, 0x2, "damaged")
	binary.LittleEndian.PutUint16(damaged[4:], 9)
	data = append(data, damaged...)
	data = append(data, ntfstest.USNV2(33, 5, 3, 0x2, "after")...)
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
	vol, _ := ntfstest.Volume()
	rec := make([]byte, ntfstest.RecordSize)
	copy(rec, vol[4*ntfstest.Cluster+21*ntfstest.RecordSize:])
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 20000; i++ {
		b := append([]byte(nil), rec...)
		for j := 0; j < 1+rng.IntN(8); j++ {
			b[rng.IntN(len(b))] = byte(rng.Uint32())
		}
		ParseRecord(b, ntfstest.Sector, 21)
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

func TestQueryCSV(t *testing.T) {
	var mft, usn bytes.Buffer
	c, _ := NewCSV(&mft, MFTColumns)
	row := func(n int, inUse bool, parent, name, created string) []string {
		r := make([]string, len(MFTColumns))
		r[0], r[2], r[5], r[6], r[11] = strconv.Itoa(n), strconv.FormatBool(inUse), parent, name, created
		return r
	}
	for i := 0; i < 1000; i++ {
		c.Write(row(i, i%10 != 0, `C:\Users`, "file"+strconv.Itoa(i)+".txt", "2026-10-30 12:00:00.0000000"))
	}
	c.Write(row(1000, true, `C:\Windows`, "evil.exe", "2026-10-29 01:00:00.0000000"))
	c.Flush()
	q := func(f Filter, offset, limit int) Page {
		p, err := QueryCSV(bytes.NewReader(mft.Bytes()), f, offset, limit)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := q(Filter{}, 0, 100); len(p.Rows) != 100 || !p.More || p.Rows[0][0] != "0" {
		t.Fatal("first page")
	}
	if p := q(Filter{}, 950, 100); len(p.Rows) != 51 || p.More {
		t.Fatal("last page", len(p.Rows), p.More)
	}
	if p := q(Filter{Contains: `windows\EVIL`}, 0, 10); len(p.Rows) != 1 || p.Rows[0][6] != "evil.exe" {
		t.Fatal("contains")
	}
	if p := q(Filter{From: "2026-10-29 00:00:00", To: "2026-10-29 23:59:59.9999999"}, 0, 10); len(p.Rows) != 1 {
		t.Fatal("time range", len(p.Rows))
	}
	if p := q(Filter{Deleted: true}, 0, 500); len(p.Rows) != 100 {
		t.Fatal("deleted", len(p.Rows))
	}
	c, _ = NewCSV(&usn, USNColumns)
	for _, reason := range []string{"FileCreate", "FileDelete|Close", "RenameOldName"} {
		r := make([]string, len(USNColumns))
		r[0], r[6], r[8], r[9] = "x.txt", `C:\Temp`, "2026-10-30 12:00:00.0000000", reason
		c.Write(r)
	}
	c.Flush()
	p, err := QueryCSV(bytes.NewReader(usn.Bytes()), Filter{Reasons: []string{"renameoldname", "FileCreate"}}, 0, 10)
	if err != nil || len(p.Rows) != 2 {
		t.Fatal("reasons", p.Rows, err)
	}
	if p, _ := QueryCSV(bytes.NewReader(usn.Bytes()), Filter{Deleted: true}, 0, 10); len(p.Rows) != 1 {
		t.Fatal("journal deletes")
	}
	if _, err := QueryCSV(bytes.NewReader(usn.Bytes()), Filter{Reasons: []string{"Nope"}}, 0, 10); err == nil {
		t.Fatal("unknown reason accepted")
	}
	if _, err := QueryCSV(strings.NewReader("a,b\n1,2\n"), Filter{}, 0, 10); err == nil {
		t.Fatal("foreign CSV accepted")
	}
	if _, err := QueryCSV(bytes.NewReader(usn.Bytes()), Filter{}, 0, MaxPage+1); err == nil {
		t.Fatal("oversized page accepted")
	}
}
