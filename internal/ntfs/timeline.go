package ntfs

import (
	"bufio"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"
)

// ScanMFT decodes the records of a $MFT copy in order. Damaged records are
// passed with their error; unused slots are skipped. r is read in 1 MiB
// chunks: on a raw volume every read is a device read.
func ScanMFT(r io.Reader, boot Boot, fn func(Record, error) error) error {
	r = bufio.NewReaderSize(r, 1<<20)
	raw := make([]byte, boot.RecordSize)
	for n := uint64(0); ; n++ {
		if _, err := io.ReadFull(r, raw); err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		} else if err != nil {
			return err
		}
		rec, err := ParseRecord(raw, boot.SectorSize, n)
		if err == ErrUnused {
			continue
		}
		if err := fn(rec, err); err != nil {
			return err
		}
	}
}

// rootRecord is the MFT record of a volume's root directory.
const rootRecord = 5

type entry struct {
	parent  uint64
	pseq    uint16
	seq     uint16
	nameOff uint32
	nameLen uint16
	named   bool
	dir     bool
}

// Index holds every record's name and parent so paths can be built for
// timeline rows and change journal entries. Memory grows with the number of
// records (about 24 bytes plus the name each).
type Index struct {
	entries []entry
	names   []byte
	dirs    map[uint64]string
}

// NewIndex returns an empty index.
func NewIndex() *Index { return &Index{dirs: map[uint64]string{}} }

// Add records a record's preferred name. Names in extension records belong
// to their base record.
func (x *Index) Add(r Record) {
	n := r.Number
	if r.Base.Record != 0 {
		n = r.Base.Record
	}
	for uint64(len(x.entries)) <= n {
		x.entries = append(x.entries, entry{})
	}
	e := &x.entries[n]
	if r.Base.Record == 0 {
		e.seq, e.dir = r.Sequence, r.Directory
	}
	name, ok := r.Name()
	if !ok || e.named && r.Base.Record != 0 {
		return
	}
	e.parent, e.pseq, e.named = name.Parent.Record, name.Parent.Sequence, true
	e.nameOff, e.nameLen = uint32(len(x.names)), uint16(min(len(name.Name), 65535))
	x.names = append(x.names, name.Name[:e.nameLen]...)
}

func (x *Index) name(n uint64) string {
	e := x.entries[n]
	return string(x.names[e.nameOff : e.nameOff+uint32(e.nameLen)])
}

// Dir returns the path of a directory record, checked against the sequence
// number a reference expects; "" when it is unknown or was reused.
func (x *Index) Dir(ref Ref) string {
	if ref.Record == rootRecord {
		return `\`
	}
	if ref.Record >= uint64(len(x.entries)) || !x.entries[ref.Record].named || x.entries[ref.Record].seq != ref.Sequence {
		return ""
	}
	if p, ok := x.dirs[ref.Record]; ok {
		return p
	}
	// Walk up to the root, at most 255 levels (NTFS paths have no cycles,
	// but a damaged volume might).
	var parts []string
	cur := ref.Record
	for depth := 0; cur != rootRecord; depth++ {
		if depth > 255 || cur >= uint64(len(x.entries)) || !x.entries[cur].named {
			return ""
		}
		e := x.entries[cur]
		parts = append(parts, x.name(cur))
		if e.parent < uint64(len(x.entries)) && e.parent != rootRecord && x.entries[e.parent].seq != e.pseq {
			return ""
		}
		cur = e.parent
	}
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		b.WriteString(`\`)
		b.WriteString(parts[i])
	}
	p := b.String()
	x.dirs[ref.Record] = p
	return p
}

// Join appends a name to a directory path.
func Join(dir, name string) string {
	if dir == `\` {
		return `\` + name
	}
	return dir + `\` + name
}

// Unknown marks a path whose parent directory is not known any more.
const Unknown = `<unknown>`

const stamp = "2006-01-02 15:04:05.0000000"

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(stamp)
}

// MFTColumns are the timeline columns for $MFT, named as common tools
// (MFTECmd) name them; 0x10 is $STANDARD_INFORMATION, 0x30 $FILE_NAME.
var MFTColumns = []string{"EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentSequenceNumber", "ParentPath", "FileName", "Extension", "FileSize", "IsDirectory", "HasAds", "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30", "SiFlags", "NameType", "UpdateSequenceNumber", "LogfileSequenceNumber"}

// USNColumns are the timeline columns for the change journal.
var USNColumns = []string{"Name", "Extension", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber", "ParentPath", "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons", "FileAttributes", "OffsetToData"}

var nameTypes = []string{"Posix", "Windows", "Dos", "DosWindows"}

func extension(name string) string {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[i:]
	}
	return ""
}

// MFTRows calls fn with a record's timeline rows and their paths, prefix
// being the volume ("C:"): one row per hard link. Records without a name
// (extension records, damaged ones) have no row.
func MFTRows(x *Index, r Record, prefix string, fn func(row []string, path string) error) error {
	if r.Base.Record != 0 {
		return nil
	}
	for _, name := range r.Links() {
		if err := fn(mftRow(x, r, name, prefix)); err != nil {
			return err
		}
	}
	return nil
}

func mftRow(x *Index, r Record, name FileName, prefix string) ([]string, string) {
	dir := x.Dir(name.Parent)
	if dir == "" {
		dir = `\` + Unknown
	}
	parent := prefix + dir
	var size int64
	ads := false
	for _, s := range r.Streams {
		if s.Name == "" && s.StartVCN == 0 {
			size = s.Size
		} else if s.Name != "" {
			ads = true
		}
	}
	nt := ""
	if int(name.Namespace) < len(nameTypes) {
		nt = nameTypes[name.Namespace]
	}
	row := []string{
		strconv.FormatUint(r.Number, 10), strconv.Itoa(int(r.Sequence)), strconv.FormatBool(r.InUse),
		strconv.FormatUint(name.Parent.Record, 10), strconv.Itoa(int(name.Parent.Sequence)), parent, name.Name, extension(name.Name),
		strconv.FormatInt(size, 10), strconv.FormatBool(r.Directory), strconv.FormatBool(ads),
		ts(r.SI.Created), ts(name.Times.Created), ts(r.SI.Modified), ts(name.Times.Modified),
		ts(r.SI.Changed), ts(name.Times.Changed), ts(r.SI.Accessed), ts(name.Times.Accessed),
		"0x" + strconv.FormatUint(uint64(r.SIFlags), 16), nt, strconv.FormatUint(r.USN, 10), strconv.FormatUint(r.LSN, 10),
	}
	return row, prefix + Join(dir, name.Name)
}

// USNRow returns a change journal entry's timeline row.
func USNRow(x *Index, u USNRecord, prefix string) ([]string, string) {
	dir := x.Dir(u.Parent)
	if dir == "" {
		dir = `\` + Unknown
	}
	parent := prefix + dir
	row := []string{
		u.Name, extension(u.Name), strconv.FormatUint(u.File.Record, 10), strconv.Itoa(int(u.File.Sequence)),
		strconv.FormatUint(u.Parent.Record, 10), strconv.Itoa(int(u.Parent.Sequence)), parent,
		strconv.FormatInt(u.USN, 10), ts(u.Time), ReasonText(u.Reason), "0x" + strconv.FormatUint(uint64(u.Attributes), 16),
		strconv.FormatInt(u.Offset, 10),
	}
	return row, prefix + Join(dir, u.Name)
}

// NewCSV returns a CSV writer with the header written.
func NewCSV(w io.Writer, columns []string) (*csv.Writer, error) {
	c := csv.NewWriter(w)
	return c, c.Write(columns)
}
