package ntfs

import (
	"io"
	"strings"
	"time"
)

// USNRecord is one change journal entry (USN_RECORD_V2 or V3).
type USNRecord struct {
	USN        int64
	Time       time.Time
	Reason     uint32
	File       Ref
	Parent     Ref
	Name       string
	Attributes uint32
	SourceInfo uint32
	// Offset is the record's position in $J.
	Offset int64
}

// reasons are the USN_REASON_* flags in the order tools list them.
var reasons = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "DataOverwrite"}, {0x00000002, "DataExtend"}, {0x00000004, "DataTruncation"},
	{0x00000010, "NamedDataOverwrite"}, {0x00000020, "NamedDataExtend"}, {0x00000040, "NamedDataTruncation"},
	{0x00000100, "FileCreate"}, {0x00000200, "FileDelete"}, {0x00000400, "EaChange"},
	{0x00000800, "SecurityChange"}, {0x00001000, "RenameOldName"}, {0x00002000, "RenameNewName"},
	{0x00004000, "IndexableChange"}, {0x00008000, "BasicInfoChange"}, {0x00010000, "HardLinkChange"},
	{0x00020000, "CompressionChange"}, {0x00040000, "EncryptionChange"}, {0x00080000, "ObjectIdChange"},
	{0x00100000, "ReparsePointChange"}, {0x00200000, "StreamChange"}, {0x00400000, "TransactedChange"},
	{0x00800000, "IntegrityChange"}, {0x80000000, "Close"},
}

// ReasonText lists the reason flags separated by "|".
func ReasonText(v uint32) string {
	var parts []string
	for _, r := range reasons {
		if v&r.bit != 0 {
			parts = append(parts, r.name)
		}
	}
	return strings.Join(parts, "|")
}

// ReasonBit returns the flag for a reason name (case-insensitive), or 0.
func ReasonBit(name string) uint32 {
	for _, r := range reasons {
		if strings.EqualFold(r.name, name) {
			return r.bit
		}
	}
	return 0
}

// parseUSN decodes one record at the start of b; ok is false when b does
// not start with a valid record.
func parseUSN(b []byte) (USNRecord, int, bool) {
	if len(b) < 8 {
		return USNRecord{}, 0, false
	}
	length := int(le32(b))
	major := le16(b[4:])
	if length < 60 || length%8 != 0 || length > len(b) || length > 4096 {
		return USNRecord{}, 0, false
	}
	var u USNRecord
	var nameLen, nameOff int
	switch major {
	case 2:
		u = USNRecord{File: ref(le64(b[8:])), Parent: ref(le64(b[16:])), USN: int64(le64(b[24:])), Time: filetime(le64(b[32:])), Reason: le32(b[40:]), SourceInfo: le32(b[44:]), Attributes: le32(b[52:])}
		nameLen, nameOff = int(le16(b[56:])), int(le16(b[58:]))
	case 3:
		if length < 76 {
			return USNRecord{}, 0, false
		}
		// 128-bit references; NTFS uses only their low 64 bits.
		u = USNRecord{File: ref(le64(b[8:])), Parent: ref(le64(b[24:])), USN: int64(le64(b[40:])), Time: filetime(le64(b[48:])), Reason: le32(b[56:]), SourceInfo: le32(b[60:]), Attributes: le32(b[68:])}
		nameLen, nameOff = int(le16(b[72:])), int(le16(b[74:]))
	default:
		return USNRecord{}, 0, false
	}
	if nameLen%2 != 0 || nameOff+nameLen > length || nameOff < 60 {
		return USNRecord{}, 0, false
	}
	u.Name = utf16le(b[nameOff : nameOff+nameLen])
	return u, length, true
}

// ScanUSN reads change journal records from r (the allocated part of $J,
// which starts at offset base in the stream). Zero-filled space between
// records and pages is skipped; unreadable bytes are skipped in 8-byte steps,
// so damage loses only the records it covers.
func ScanUSN(r io.Reader, base int64, fn func(USNRecord) error) error {
	const chunk = 1 << 20
	buf := make([]byte, 0, chunk+4096)
	pos := base
	eof := false
	for {
		for !eof && len(buf) < chunk {
			n, err := r.Read(buf[len(buf):cap(buf)])
			buf = buf[:len(buf)+n]
			if err == io.EOF {
				eof = true
			} else if err != nil {
				return err
			}
		}
		i := 0
		for i+8 <= len(buf) {
			if le32(buf[i:]) == 0 {
				i += 8
				continue
			}
			u, n, ok := parseUSN(buf[i:])
			if !ok {
				// A record cut off at the end of the buffer waits for more data.
				if !eof && len(buf)-i < 4096 {
					break
				}
				i += 8
				continue
			}
			u.Offset = pos + int64(i)
			if err := fn(u); err != nil {
				return err
			}
			i += n
		}
		pos += int64(i)
		buf = append(buf[:0], buf[i:]...)
		if eof && len(buf) < 8 {
			return nil
		}
		if eof && i == 0 {
			return nil
		}
	}
}
