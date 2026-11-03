// Package registry reads Windows registry hive files (regf): keys, values
// and their last write times, after replaying the hive's transaction logs
// (.LOG1, .LOG2) when the hive was not written completely. It uses only the
// standard library; every offset and length is checked before use, and
// walks are bounded so a crafted hive cannot loop.
package registry

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// ErrCorrupt reports a structure that does not decode.
var ErrCorrupt = errors.New("registry: corrupt or unsupported hive")

// MaxHive is the largest hive (and transaction log) read.
const MaxHive = 512 << 20

const (
	baseBlock = 4096
	// Values larger than this are stored in segments (hive version 1.4+).
	segment     = 16344
	maxValues   = 1 << 20
	maxSubkeys  = 1 << 20
	maxListNest = 2
)

var le = binary.LittleEndian

// Hive is an open hive.
type Hive struct {
	bins  []byte
	root  uint32
	minor uint32
	// LastWritten is the base block's time; Dirty reports that the hive
	// needed its transaction logs, and Replayed how many log entries were
	// applied.
	LastWritten time.Time
	Dirty       bool
	Replayed    int
}

// Open reads a hive, replaying the transaction logs given (the contents of
// .LOG1 and .LOG2) when the hive is dirty. The hive's bytes may be changed.
func Open(b []byte, logs ...[]byte) (*Hive, error) {
	if len(b) < baseBlock || string(b[:4]) != "regf" {
		return nil, ErrCorrupt
	}
	h := &Hive{Dirty: dirty(b)}
	if h.Dirty {
		b, h.Replayed = replay(b, logs)
	}
	size := int(le.Uint32(b[40:]))
	if size <= 0 || size > len(b)-baseBlock {
		// A short hive (cut off or still being written) keeps what it has.
		size = len(b) - baseBlock
	}
	h.bins = b[baseBlock : baseBlock+size]
	h.root = le.Uint32(b[36:])
	h.minor = le.Uint32(b[24:])
	h.LastWritten = filetime(le.Uint64(b[12:]))
	if _, err := h.Root(); err != nil {
		return nil, err
	}
	return h, nil
}

// checksum is the XOR-32 of a base block's first 508 bytes.
func checksum(b []byte) uint32 {
	var x uint32
	for i := 0; i < 508; i += 4 {
		x ^= le.Uint32(b[i:])
	}
	switch x {
	case 0:
		return 1
	case 0xFFFFFFFF:
		return 0xFFFFFFFE
	}
	return x
}

// dirty: the sequence numbers differ (a write did not finish) or the base
// block does not check.
func dirty(b []byte) bool {
	return le.Uint32(b[4:]) != le.Uint32(b[8:]) || checksum(b) != le.Uint32(b[508:])
}

// cell returns a cell's data. Cells free in the hive (positive sizes) are
// still read: a reference to one means the hive was cut off mid-change.
func (h *Hive) cell(off uint32) ([]byte, error) {
	o := int(off)
	if off == 0xFFFFFFFF || o < 0 || o+4 > len(h.bins) {
		return nil, ErrCorrupt
	}
	size := int(int32(le.Uint32(h.bins[o:])))
	if size < 0 {
		size = -size
	}
	if size < 8 || size > len(h.bins)-o {
		return nil, ErrCorrupt
	}
	return h.bins[o+4 : o+size], nil
}

// Key is a key node.
type Key struct {
	h *Hive
	d []byte
}

// Root returns the hive's root key.
func (h *Hive) Root() (Key, error) { return h.key(h.root) }

func (h *Hive) key(off uint32) (Key, error) {
	d, err := h.cell(off)
	if err != nil || len(d) < 76 || string(d[:2]) != "nk" {
		return Key{}, ErrCorrupt
	}
	return Key{h, d}, nil
}

// Name is the key's name.
func (k Key) Name() string {
	n := int(le.Uint16(k.d[72:]))
	name := k.d[76:min(76+n, len(k.d))]
	if le.Uint16(k.d[2:])&0x20 != 0 {
		return latin1(name)
	}
	return utf16s(name)
}

// LastWrite is the key's last write time.
func (k Key) LastWrite() time.Time { return filetime(le.Uint64(k.d[4:])) }

// Subkeys lists the key's subkeys.
func (k Key) Subkeys() ([]Key, error) {
	count := le.Uint32(k.d[20:])
	if count == 0 {
		return nil, nil
	}
	if count > maxSubkeys {
		return nil, ErrCorrupt
	}
	var out []Key
	err := k.h.subkeyList(le.Uint32(k.d[28:]), 0, &out)
	return out, err
}

func (h *Hive) subkeyList(off uint32, depth int, out *[]Key) error {
	d, err := h.cell(off)
	if err != nil || len(d) < 4 {
		return ErrCorrupt
	}
	n := int(le.Uint16(d[2:]))
	switch string(d[:2]) {
	case "lf", "lh", "li":
		step := 8
		if d[1] == 'i' {
			step = 4
		}
		if 4+n*step > len(d) {
			return ErrCorrupt
		}
		for i := range n {
			if len(*out) >= maxSubkeys {
				return ErrCorrupt
			}
			k, err := h.key(le.Uint32(d[4+i*step:]))
			if err != nil {
				return err
			}
			*out = append(*out, k)
		}
	case "ri":
		if depth >= maxListNest || 4+n*4 > len(d) {
			return ErrCorrupt
		}
		for i := range n {
			if err := h.subkeyList(le.Uint32(d[4+i*4:]), depth+1, out); err != nil {
				return err
			}
		}
	default:
		return ErrCorrupt
	}
	return nil
}

// Subkey opens a path of subkeys below the key ("A\B"), ignoring case.
func (k Key) Subkey(path string) (Key, bool) {
	for name := range strings.SplitSeq(path, `\`) {
		subs, err := k.Subkeys()
		if err != nil {
			return Key{}, false
		}
		found := false
		for _, s := range subs {
			if strings.EqualFold(s.Name(), name) {
				k, found = s, true
				break
			}
		}
		if !found {
			return Key{}, false
		}
	}
	return k, true
}

// Values lists the key's values.
func (k Key) Values() ([]Value, error) {
	count := int(le.Uint32(k.d[36:]))
	if count == 0 {
		return nil, nil
	}
	if count > maxValues {
		return nil, ErrCorrupt
	}
	list, err := k.h.cell(le.Uint32(k.d[40:]))
	if err != nil || count*4 > len(list) {
		return nil, ErrCorrupt
	}
	out := make([]Value, 0, count)
	for i := range count {
		d, err := k.h.cell(le.Uint32(list[i*4:]))
		if err != nil || len(d) < 20 || string(d[:2]) != "vk" {
			return out, ErrCorrupt
		}
		out = append(out, Value{k.h, d})
	}
	return out, nil
}

// Value finds a value by name ("" is the default value), ignoring case.
func (k Key) Value(name string) (Value, bool) {
	values, _ := k.Values()
	for _, v := range values {
		if strings.EqualFold(v.Name(), name) {
			return v, true
		}
	}
	return Value{}, false
}

// Value types.
const (
	None         = 0
	String       = 1
	ExpandString = 2
	Binary       = 3
	DWord        = 4
	DWordBig     = 5
	Link         = 6
	MultiString  = 7
	QWord        = 11
)

// Value is a value node.
type Value struct {
	h *Hive
	d []byte
}

// Name is the value's name; "" for the default value.
func (v Value) Name() string {
	n := int(le.Uint16(v.d[2:]))
	name := v.d[20:min(20+n, len(v.d))]
	if le.Uint16(v.d[16:])&1 != 0 {
		return latin1(name)
	}
	return utf16s(name)
}

// Type is the value's type.
func (v Value) Type() uint32 { return le.Uint32(v.d[12:]) }

// Data returns the value's data.
func (v Value) Data() ([]byte, error) {
	size := le.Uint32(v.d[4:])
	if size&0x80000000 != 0 {
		// Up to four bytes are stored in the offset field itself.
		return v.d[8 : 8+min(size&0x7FFFFFFF, 4)], nil
	}
	if size == 0 {
		return nil, nil
	}
	if size > MaxHive {
		return nil, ErrCorrupt
	}
	c, err := v.h.cell(le.Uint32(v.d[8:]))
	if err != nil {
		return nil, err
	}
	if size > segment && v.h.minor >= 4 && len(c) >= 8 && string(c[:2]) == "db" {
		n := int(le.Uint16(c[2:]))
		list, err := v.h.cell(le.Uint32(c[4:]))
		if err != nil || n*4 > len(list) {
			return nil, ErrCorrupt
		}
		out := make([]byte, 0, size)
		for i := 0; i < n && len(out) < int(size); i++ {
			s, err := v.h.cell(le.Uint32(list[i*4:]))
			if err != nil {
				return nil, err
			}
			out = append(out, s[:min(len(s), segment, int(size)-len(out))]...)
		}
		if len(out) != int(size) {
			return nil, ErrCorrupt
		}
		return out, nil
	}
	if int(size) > len(c) {
		return nil, ErrCorrupt
	}
	return c[:size], nil
}

// Text returns the value's data as text: strings as they are (several
// separated by "|"), numbers in decimal, anything else as hexadecimal (at
// most 1,024 bytes).
func (v Value) Text() string {
	d, err := v.Data()
	if err != nil {
		return ""
	}
	switch v.Type() {
	case String, ExpandString, Link:
		return strings.TrimRight(utf16s(d), "\x00")
	case MultiString:
		var parts []string
		for s := range strings.SplitSeq(strings.TrimRight(utf16s(d), "\x00"), "\x00") {
			parts = append(parts, s)
		}
		return strings.Join(parts, "|")
	case DWord:
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(le.Uint32(d)), 10)
		}
	case DWordBig:
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(d)), 10)
		}
	case QWord:
		if len(d) >= 8 {
			return strconv.FormatUint(le.Uint64(d), 10)
		}
	}
	const hexdigits = "0123456789abcdef"
	d = d[:min(len(d), 1024)]
	out := make([]byte, 0, 2*len(d))
	for _, c := range d {
		out = append(out, hexdigits[c>>4], hexdigits[c&15])
	}
	return string(out)
}

// Uint returns a DWORD or QWORD value.
func (v Value) Uint() (uint64, bool) {
	d, err := v.Data()
	switch {
	case err != nil:
	case v.Type() == DWord && len(d) >= 4:
		return uint64(le.Uint32(d)), true
	case v.Type() == QWord && len(d) >= 8:
		return le.Uint64(d), true
	}
	return 0, false
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

func utf16s(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// FileTime converts a FILETIME; zero and out-of-range values are zero.
func FileTime(v uint64) time.Time { return filetime(v) }

func filetime(v uint64) time.Time {
	const epoch = 116444736000000000
	if v <= epoch || v > epoch+uint64(400*365*24*3600)*10_000_000 {
		return time.Time{}
	}
	return time.Unix(0, int64(v-epoch)*100).UTC()
}

// UTF16 decodes UTF-16LE text up to the first NUL.
func UTF16(b []byte) string {
	s := utf16s(b)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
}
