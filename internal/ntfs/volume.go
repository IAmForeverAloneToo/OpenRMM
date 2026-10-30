package ntfs

import (
	"errors"
	"io"
	"sort"
)

// ErrNotNTFS reports a volume that is not NTFS.
var ErrNotNTFS = errors.New("ntfs: not an NTFS volume")

// Boot is the volume geometry from the boot sector.
type Boot struct {
	SectorSize  int
	ClusterSize int
	RecordSize  int
	MFTCluster  int64
	Serial      uint64
}

// ParseBoot decodes and checks an NTFS boot sector.
func ParseBoot(b []byte) (Boot, error) {
	if len(b) < 512 || string(b[3:11]) != "NTFS    " {
		return Boot{}, ErrNotNTFS
	}
	sector := int(le16(b[0x0B:]))
	if sector != 512 && sector != 1024 && sector != 2048 && sector != 4096 {
		return Boot{}, ErrCorrupt
	}
	spc := int(b[0x0D])
	if spc > 0x80 {
		spc = 1 << (256 - spc)
	}
	cluster := sector * spc
	if spc == 0 || spc&(spc-1) != 0 || cluster > 2<<20 {
		return Boot{}, ErrCorrupt
	}
	record := int(int8(b[0x40]))
	if record > 0 {
		record *= cluster
	} else if record < 0 && record > -31 {
		record = 1 << -record
	}
	if record < 1024 || record > 65536 || record%sector != 0 {
		return Boot{}, ErrCorrupt
	}
	mft := int64(le64(b[0x30:]))
	if mft <= 0 {
		return Boot{}, ErrCorrupt
	}
	return Boot{SectorSize: sector, ClusterSize: cluster, RecordSize: record, MFTCluster: mft, Serial: le64(b[0x48:])}, nil
}

// Volume reads metadata from a raw NTFS volume (a device or an image).
type Volume struct {
	Boot
	r   io.ReaderAt
	mft *Reader
}

// Open reads the boot sector and the $MFT's own record. A fragmented $MFT
// whose runs continue in extension records is followed through its
// attribute list.
func Open(r io.ReaderAt) (*Volume, error) {
	b := make([]byte, 512)
	if _, err := r.ReadAt(b, 0); err != nil {
		return nil, err
	}
	boot, err := ParseBoot(b)
	if err != nil {
		return nil, err
	}
	v := &Volume{Boot: boot, r: r}
	raw := make([]byte, boot.RecordSize)
	if _, err := r.ReadAt(raw, boot.MFTCluster*int64(boot.ClusterSize)); err != nil {
		return nil, err
	}
	rec, err := ParseRecord(raw, boot.SectorSize, 0)
	if err != nil {
		return nil, err
	}
	// The first fragment, which covers the start of the MFT, is enough to
	// read the extension records that hold the others.
	for _, s := range rec.Streams {
		if s.Name == "" && !s.Resident && s.StartVCN == 0 {
			v.mft = &Reader{v: v, runs: s.Runs, size: s.Size}
		}
	}
	if v.mft == nil {
		return nil, ErrCorrupt
	}
	full, err := v.OpenStream(rec, "")
	if err != nil {
		return nil, err
	}
	v.mft = full
	return v, nil
}

// MFT returns a reader over the whole $MFT.
func (v *Volume) MFT() *Reader { return v.mft }

// Record reads and decodes one MFT record.
func (v *Volume) Record(n uint64) (Record, error) {
	raw := make([]byte, v.RecordSize)
	if _, err := v.mft.ReadAt(raw, int64(n)*int64(v.RecordSize)); err != nil {
		return Record{}, err
	}
	return ParseRecord(raw, v.SectorSize, n)
}

// OpenStream returns a reader for a record's data stream (name empty for
// the main data), gathering fragments from extension records.
func (v *Volume) OpenStream(rec Record, name string) (*Reader, error) {
	var parts []Stream
	for _, s := range rec.Streams {
		if s.Name == name {
			parts = append(parts, s)
		}
	}
	list := rec.AttributeList
	if rec.ListRuns != nil {
		if rec.ListSize < 0 || rec.ListSize > 16<<20 {
			return nil, ErrCorrupt
		}
		b := make([]byte, rec.ListSize)
		if _, err := (&Reader{v: v, runs: rec.ListRuns, size: rec.ListSize}).ReadAt(b, 0); err != nil && err != io.EOF {
			return nil, err
		}
		l, err := ParseAttributeList(b)
		if err != nil {
			return nil, err
		}
		list = l
	}
	seen := map[uint64]bool{rec.Number: true}
	for _, e := range list {
		if e.Type != attrData || e.Name != name || seen[e.Record.Record] {
			continue
		}
		seen[e.Record.Record] = true
		ext, err := v.Record(e.Record.Record)
		if err != nil {
			return nil, err
		}
		for _, s := range ext.Streams {
			if s.Name == name {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) == 0 {
		return nil, errors.New("ntfs: stream not found")
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].StartVCN < parts[j].StartVCN })
	first := parts[0]
	if first.Resident {
		return &Reader{data: first.Data, size: int64(len(first.Data)), resident: true}, nil
	}
	if first.Compressed {
		return nil, errors.New("ntfs: compressed streams are not supported")
	}
	rd := &Reader{v: v, size: first.Size}
	var vcn int64
	for _, p := range parts {
		if p.Resident || p.StartVCN != vcn {
			return nil, ErrCorrupt
		}
		for _, run := range p.Runs {
			rd.runs = append(rd.runs, run)
			vcn += run.Length
		}
	}
	return rd, nil
}

// Reader reads a stream through its runs; holes read as zeros.
type Reader struct {
	v        *Volume
	runs     []Run
	size     int64
	data     []byte
	resident bool
}

// Size is the stream's length in bytes.
func (r *Reader) Size() int64 { return r.size }

// ReadAt implements io.ReaderAt.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, ErrCorrupt
	}
	if off >= r.size {
		return 0, io.EOF
	}
	want := p
	if int64(len(want)) > r.size-off {
		want = want[:r.size-off]
	}
	if r.resident {
		n := copy(want, r.data[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	cs := int64(r.v.ClusterSize)
	done := 0
	for done < len(want) {
		pos := off + int64(done)
		vcn, inner := pos/cs, pos%cs
		run, start, ok := r.find(vcn)
		if !ok {
			return done, ErrCorrupt
		}
		avail := (start+run.Length)*cs - pos
		chunk := want[done:]
		if int64(len(chunk)) > avail {
			chunk = chunk[:avail]
		}
		if run.Sparse {
			clear(chunk)
		} else if _, err := r.v.r.ReadAt(chunk, (run.LCN+vcn-start)*cs+inner); err != nil {
			return done, err
		}
		done += len(chunk)
	}
	if len(want) < len(p) {
		return done, io.EOF
	}
	return done, nil
}

// find returns the run that holds a VCN and the run's first VCN.
func (r *Reader) find(vcn int64) (Run, int64, bool) {
	var start int64
	for _, run := range r.runs {
		if vcn < start+run.Length {
			return run, start, true
		}
		start += run.Length
	}
	return Run{}, 0, false
}

// Allocated returns the offset of the first byte that is not in a sparse
// hole (the stream's size when all of it is sparse). The USN journal keeps
// only its recent part allocated.
func (r *Reader) Allocated() int64 {
	if r.resident {
		return 0
	}
	var vcn int64
	for _, run := range r.runs {
		if !run.Sparse {
			return min(vcn*int64(r.v.ClusterSize), r.size)
		}
		vcn += run.Length
	}
	return r.size
}
