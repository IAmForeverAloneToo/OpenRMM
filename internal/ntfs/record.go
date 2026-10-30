// Package ntfs reads NTFS metadata from a raw volume or from copies of its
// system files: MFT records, the data runs of any stream, and the USN change
// journal. It uses only the standard library and never writes to a volume.
//
// Every length and offset read from disk is checked before use; a damaged
// record is reported as an error for that record and never stops a scan.
package ntfs

import (
	"encoding/binary"
	"errors"
	"time"
	"unicode/utf16"
)

// ErrCorrupt reports a structure that does not decode.
var ErrCorrupt = errors.New("ntfs: corrupt structure")

// Attribute types used here.
const (
	attrStandardInformation = 0x10
	attrAttributeList       = 0x20
	attrFileName            = 0x30
	attrData                = 0x80
	attrEnd                 = 0xFFFFFFFF
)

// Ref is a file reference: a record number and the record's sequence
// number when the reference was made.
type Ref struct {
	Record   uint64
	Sequence uint16
}

func ref(v uint64) Ref { return Ref{Record: v & 0xFFFFFFFFFFFF, Sequence: uint16(v >> 48)} }

// Times are the four NTFS timestamps of a standard information or file
// name attribute.
type Times struct {
	Created, Modified, Changed, Accessed time.Time
}

// FileName is a $FILE_NAME attribute.
type FileName struct {
	Parent    Ref
	Name      string
	Namespace uint8 // 0 POSIX, 1 Win32, 2 DOS, 3 Win32 and DOS
	Times     Times
	Size      uint64
	Flags     uint32
}

// Stream is a $DATA attribute (or one fragment of it): Name is empty for a
// file's main data and set for an alternate data stream.
type Stream struct {
	Name       string
	Resident   bool
	Data       []byte // resident value
	Size       int64  // real size (from the first fragment)
	StartVCN   int64
	Runs       []Run
	Sparse     bool
	Compressed bool
}

// AttributeListEntry names a record that holds part of a file's attributes.
type AttributeListEntry struct {
	Type     uint32
	Name     string
	StartVCN int64
	Record   Ref
}

// Record is one decoded MFT record.
type Record struct {
	Number        uint64
	Sequence      uint16
	InUse         bool
	Directory     bool
	Base          Ref // non-zero for an extension record
	LSN           uint64
	HasSI         bool
	SI            Times
	SIFlags       uint32
	USN           uint64
	Names         []FileName
	Streams       []Stream
	AttributeList []AttributeListEntry
	// ListRuns is a non-resident attribute list, read by the volume.
	ListRuns []Run
	ListSize int64
}

// filetime converts a Windows FILETIME; zero stays the zero time.
func filetime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	const epoch = 116444736000000000 // 1601-01-01 to 1970-01-01 in 100 ns units
	t := int64(v) - epoch
	return time.Unix(t/10000000, (t%10000000)*100).UTC()
}

func times(b []byte) Times {
	return Times{filetime(le64(b)), filetime(le64(b[8:])), filetime(le64(b[16:])), filetime(le64(b[24:]))}
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// fixup applies the update sequence array in place: the last two bytes of
// every sector were replaced on disk by the sequence number.
func fixup(b []byte, sector int) error {
	if len(b) < 8 || sector < 2 || len(b)%sector != 0 {
		return ErrCorrupt
	}
	off, count := int(le16(b[4:])), int(le16(b[6:]))
	if count != len(b)/sector+1 || off+2*count > len(b) {
		return ErrCorrupt
	}
	usn := le16(b[off:])
	for i := 1; i < count; i++ {
		end := i*sector - 2
		if le16(b[end:]) != usn {
			return ErrCorrupt
		}
		copy(b[end:end+2], b[off+2*i:off+2*i+2])
	}
	return nil
}

// ParseRecord decodes a FILE record. It applies the fixups to its own copy;
// a record that was never used (all zero) is reported as ErrUnused.
func ParseRecord(raw []byte, sector int, number uint64) (Record, error) {
	if len(raw) < 48 || string(raw[:4]) != "FILE" {
		if len(raw) >= 4 && raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
			return Record{}, ErrUnused
		}
		return Record{}, ErrCorrupt
	}
	b := append([]byte(nil), raw...)
	if err := fixup(b, sector); err != nil {
		return Record{}, err
	}
	flags := le16(b[0x16:])
	r := Record{Number: number, Sequence: le16(b[0x10:]), LSN: le64(b[0x08:]), InUse: flags&1 != 0, Directory: flags&2 != 0, Base: ref(le64(b[0x20:]))}
	used := int(le32(b[0x18:]))
	if used > len(b) || used < 0x30 {
		return r, ErrCorrupt
	}
	pos := int(le16(b[0x14:]))
	for pos+8 <= used {
		typ := le32(b[pos:])
		if typ == attrEnd {
			break
		}
		length := int(le32(b[pos+4:]))
		if length < 0x18 || pos+length > used || length%8 != 0 {
			return r, ErrCorrupt
		}
		if err := r.attribute(b[pos : pos+length]); err != nil {
			return r, err
		}
		pos += length
	}
	return r, nil
}

// ErrUnused reports a record slot that was never written.
var ErrUnused = errors.New("ntfs: unused record")

func (r *Record) attribute(a []byte) error {
	typ := le32(a)
	nonResident := a[8] != 0
	nameLen, nameOff := int(a[9]), int(le16(a[10:]))
	if nameOff+2*nameLen > len(a) {
		return ErrCorrupt
	}
	name := utf16le(a[nameOff : nameOff+2*nameLen])
	flags := le16(a[12:])
	var value []byte
	if !nonResident {
		vlen, voff := int(le32(a[16:])), int(le16(a[20:]))
		if voff+vlen > len(a) || vlen < 0 {
			return ErrCorrupt
		}
		value = a[voff : voff+vlen]
	} else if len(a) < 0x40 {
		return ErrCorrupt
	}
	switch typ {
	case attrStandardInformation:
		if nonResident || len(value) < 0x24 {
			return ErrCorrupt
		}
		r.HasSI, r.SI, r.SIFlags = true, times(value), le32(value[0x20:])
		if len(value) >= 0x48 {
			r.USN = le64(value[0x40:])
		}
	case attrFileName:
		if nonResident || len(value) < 0x42 {
			return ErrCorrupt
		}
		n := int(value[0x40])
		if 0x42+2*n > len(value) {
			return ErrCorrupt
		}
		r.Names = append(r.Names, FileName{Parent: ref(le64(value)), Times: times(value[8:]), Size: le64(value[0x30:]), Flags: le32(value[0x38:]), Namespace: value[0x41], Name: utf16le(value[0x42 : 0x42+2*n])})
	case attrData:
		s := Stream{Name: name, Resident: !nonResident, Sparse: flags&0x8000 != 0, Compressed: flags&0x0001 != 0}
		if nonResident {
			s.StartVCN = int64(le64(a[0x10:]))
			s.Size = int64(le64(a[0x30:]))
			runs, err := decodeRuns(a, int(le16(a[0x20:])))
			if err != nil {
				return err
			}
			s.Runs = runs
		} else {
			s.Data, s.Size = value, int64(len(value))
		}
		r.Streams = append(r.Streams, s)
	case attrAttributeList:
		if nonResident {
			runs, err := decodeRuns(a, int(le16(a[0x20:])))
			if err != nil {
				return err
			}
			r.ListRuns, r.ListSize = runs, int64(le64(a[0x30:]))
			return nil
		}
		list, err := ParseAttributeList(value)
		if err != nil {
			return err
		}
		r.AttributeList = list
	}
	return nil
}

// ParseAttributeList decodes an $ATTRIBUTE_LIST value.
func ParseAttributeList(b []byte) ([]AttributeListEntry, error) {
	var out []AttributeListEntry
	for pos := 0; pos+0x1A <= len(b); {
		length := int(le16(b[pos+4:]))
		nameLen, nameOff := int(b[pos+6]), int(b[pos+7])
		if length < 0x1A || pos+length > len(b) || nameOff+2*nameLen > length {
			return out, ErrCorrupt
		}
		e := b[pos : pos+length]
		out = append(out, AttributeListEntry{Type: le32(e), StartVCN: int64(le64(e[8:])), Record: ref(le64(e[0x10:])), Name: utf16le(e[nameOff : nameOff+2*nameLen])})
		pos += length
	}
	return out, nil
}

// Run is a contiguous extent: Length clusters from LCN, or a sparse hole.
type Run struct {
	LCN    int64
	Length int64
	Sparse bool
}

// decodeRuns reads a mapping-pairs array starting at off within attribute a.
func decodeRuns(a []byte, off int) ([]Run, error) {
	var runs []Run
	var lcn int64
	for off < len(a) {
		h := a[off]
		if h == 0 {
			return runs, nil
		}
		ls, os := int(h&0x0F), int(h>>4)
		if ls == 0 || ls > 8 || os > 8 || off+1+ls+os > len(a) {
			return nil, ErrCorrupt
		}
		length := int64(unsigned(a[off+1 : off+1+ls]))
		if length <= 0 {
			return nil, ErrCorrupt
		}
		if os == 0 {
			runs = append(runs, Run{Length: length, Sparse: true})
		} else {
			lcn += signed(a[off+1+ls : off+1+ls+os])
			if lcn < 0 {
				return nil, ErrCorrupt
			}
			runs = append(runs, Run{LCN: lcn, Length: length})
		}
		off += 1 + ls + os
	}
	return nil, ErrCorrupt
}

func unsigned(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func signed(b []byte) int64 {
	v := unsigned(b)
	if n := uint(len(b)) * 8; n < 64 && v&(1<<(n-1)) != 0 {
		v |= ^uint64(0) << n
	}
	return int64(v)
}

// Name returns the record's preferred file name: Win32 over POSIX over DOS.
func (r Record) Name() (FileName, bool) {
	best, rank := FileName{}, -1
	for _, n := range r.Names {
		k := 0
		switch n.Namespace {
		case 1, 3:
			k = 3
		case 0:
			k = 2
		case 2:
			k = 1
		}
		if k > rank {
			best, rank = n, k
		}
	}
	return best, rank >= 0
}
