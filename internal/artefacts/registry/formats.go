package registry

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ShimEntry is one AppCompatCache (ShimCache) entry.
type ShimEntry struct {
	Path     string
	Modified time.Time
}

// AppCompatCache decodes the AppCompatCache value of Windows 10 and 11:
// a header of 0x30 or 0x34 bytes, then entries signed "10ts".
func AppCompatCache(d []byte) ([]ShimEntry, error) {
	if len(d) < 4 {
		return nil, ErrCorrupt
	}
	pos := int(le.Uint32(d))
	if pos != 0x30 && pos != 0x34 {
		return nil, fmt.Errorf("unsupported AppCompatCache format (header 0x%X); Windows 10 and later are read", pos)
	}
	var out []ShimEntry
	for pos+12 <= len(d) && len(out) < 100_000 {
		e := d[pos:]
		if string(e[:4]) != "10ts" {
			break
		}
		size := int(le.Uint32(e[8:]))
		if size < 14 || 12+size > len(e) {
			return out, ErrCorrupt
		}
		body := e[12 : 12+size]
		n := int(le.Uint16(body))
		if 2+n+8 > len(body) {
			return out, ErrCorrupt
		}
		out = append(out, ShimEntry{Path: utf16s(body[2 : 2+n]), Modified: filetime(le.Uint64(body[2+n:]))})
		pos += 12 + size
	}
	return out, nil
}

// ShellItem is one decoded shell item of a ShellBags entry.
type ShellItem struct {
	// Type names the item kind: Root folder, Drive, Folder, File,
	// Network, URI or Item 0xNN.
	Type     string
	Name     string
	Modified time.Time
	Created  time.Time
	Accessed time.Time
	// MFTEntry and MFTSequence identify a folder in its volume's MFT
	// (Windows Vista and later), when recorded.
	MFTEntry    uint64
	MFTSequence uint16
}

// Known folders of root shell items.
var knownFolders = map[string]string{
	"20D04FE0-3AEA-1069-A2D8-08002B30309D": "This PC",
	"59031A47-3F72-44A7-89C5-5595FE6B30EE": "User profile",
	"F02C1A0D-BE21-4350-88B0-7367FC96EF3C": "Network",
	"26EE0668-A00A-44D7-9371-BEB064C98683": "Control Panel",
	"450D8FBA-AD25-11D0-98A8-0800361B1103": "Documents",
	"645FF040-5081-101B-9F08-00AA002F954E": "Recycle Bin",
	"031E4825-7B94-4DC3-B131-E946B44C8DD5": "Libraries",
	"679F85CB-0220-4080-B29B-5540CC05AAB6": "Quick access",
	"088E3905-0323-4B02-9826-5D99428E115F": "Downloads",
	"374DE290-123F-4565-9164-39C4925E467B": "Downloads",
	"24AD3AD4-A569-4530-98E1-AB02F9417AA8": "Pictures",
	"B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
	"D3162B92-9365-467A-956B-92703ACA08AF": "Documents",
	"3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE": "Music",
	"F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A": "Videos",
	"018D5C66-4533-4307-9B53-224DE2ED1FE6": "OneDrive",
}

// GUID formats 16 bytes in registry form.
func GUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", le.Uint32(b), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:16])
}

// ParseShellItem decodes a shell item (with its 2-byte size).
func ParseShellItem(d []byte) (ShellItem, error) {
	if len(d) < 3 {
		return ShellItem{}, ErrCorrupt
	}
	if n := int(le.Uint16(d)); n >= 3 && n <= len(d) {
		d = d[:n]
	}
	class := d[2]
	switch {
	case class == 0x1F && len(d) >= 20:
		g := GUID(d[4:20])
		name := knownFolders[g]
		if name == "" {
			name = "{" + g + "}"
		}
		return ShellItem{Type: "Root folder", Name: name}, nil
	case class >= 0x20 && class <= 0x2F:
		if class == 0x2E && len(d) >= 20 {
			return ShellItem{Type: "Root folder", Name: "{" + GUID(d[4:20]) + "}"}, nil
		}
		return ShellItem{Type: "Drive", Name: cstring(d[3:])}, nil
	case class >= 0x30 && class <= 0x3F && len(d) >= 14:
		it := ShellItem{Type: "File", Modified: fatTime(le.Uint16(d[8:]), le.Uint16(d[10:]))}
		if class&0x01 != 0 {
			it.Type = "Folder"
		}
		if class&0x04 != 0 {
			it.Name = UTF16(d[14:])
		} else {
			it.Name = cstring(d[14:])
		}
		// The 0xBEEF0004 extension block has the long name, more times
		// and the MFT reference.
		if i := bytes.Index(d, []byte{0x04, 0x00, 0xEF, 0xBE}); i >= 4 {
			ext := d[i-4:]
			version := le.Uint16(ext[2:])
			if len(ext) >= 18 {
				it.Created = fatTime(le.Uint16(ext[8:]), le.Uint16(ext[10:]))
				it.Accessed = fatTime(le.Uint16(ext[12:]), le.Uint16(ext[14:]))
			}
			if version >= 7 && len(ext) >= 28 {
				ref := le.Uint64(ext[20:])
				it.MFTEntry, it.MFTSequence = ref&0xFFFFFFFFFFFF, uint16(ref>>48)
			}
			at := 0
			switch {
			case version >= 9:
				at = 46
			case version >= 8:
				at = 42
			case version >= 7:
				at = 38
			case version >= 3:
				at = 20
			}
			if at > 0 && at < len(ext) {
				if long := UTF16(ext[at:]); long != "" {
					it.Name = long
				}
			}
		}
		return it, nil
	case class >= 0x40 && class <= 0x4F && len(d) >= 6:
		return ShellItem{Type: "Network", Name: cstring(d[5:])}, nil
	case class == 0x61 && len(d) >= 4:
		// URI items keep the address as UTF-16 or ASCII after a header;
		// the printable text is shown.
		return ShellItem{Type: "URI", Name: printable(d[4:])}, nil
	}
	return ShellItem{Type: fmt.Sprintf("Item 0x%02X", class)}, nil
}

// fatTime decodes a FAT date and time (2-second resolution).
func fatTime(date, tm uint16) time.Time {
	if date == 0 {
		return time.Time{}
	}
	y, m, d := 1980+int(date>>9), time.Month(date>>5&15), int(date&31)
	if m < 1 || m > 12 || d < 1 || d > 31 {
		return time.Time{}
	}
	return time.Date(y, m, d, int(tm>>11), int(tm>>5&63), int(tm&31)*2, 0, time.UTC)
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return latin1(b)
}

// printable keeps the readable text of mixed data.
func printable(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			s.WriteByte(c)
		}
	}
	return s.String()
}

// Rot13 decodes UserAssist value names.
func Rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}
