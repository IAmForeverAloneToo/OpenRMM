// Package evtx reads Windows event log files (.evtx): every record's
// System fields and event data, rendered from the chunks' binary XML and
// templates. Messages are not formatted (they live in the providers' DLLs
// on the device). It uses only the standard library; every offset is
// checked, and a damaged chunk or record is skipped without stopping.
package evtx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrCorrupt reports a file that is not an event log.
var ErrCorrupt = errors.New("evtx: not an event log file")

const (
	headerSize = 4096
	chunkSize  = 65536
)

var le = binary.LittleEndian

// Field is one named value of an event's data.
type Field struct{ Name, Value string }

// Event is one rendered record.
type Event struct {
	RecordID uint64
	// System holds the System element's fields: Provider, EventID,
	// Qualifiers, Version, Level, Task, Opcode, Keywords, TimeCreated,
	// EventRecordID, ActivityID, ProcessID, ThreadID, Channel, Computer
	// and UserID.
	System map[string]string
	Data   []Field
}

// Stats counts what a scan skipped.
type Stats struct {
	Chunks, BadChunks, Records, BadRecords int
}

// Scan reads every chunk of an event log and calls fn for each record that
// renders. Damaged chunks and records are counted and skipped.
func Scan(r io.ReaderAt, size int64, fn func(Event) error) (Stats, error) {
	var st Stats
	head := make([]byte, 8)
	if size < headerSize || r == nil {
		return st, ErrCorrupt
	}
	if _, err := r.ReadAt(head, 0); err != nil || string(head) != "ElfFile\x00" {
		return st, ErrCorrupt
	}
	buf := make([]byte, chunkSize)
	for off := int64(headerSize); off+chunkSize <= size; off += chunkSize {
		if _, err := r.ReadAt(buf, off); err != nil {
			return st, err
		}
		if string(buf[:8]) != "ElfChnk\x00" {
			// Unused space at the end of a log is zero.
			if buf[0] != 0 {
				st.BadChunks++
			}
			continue
		}
		st.Chunks++
		c := &chunk{b: buf, names: map[uint32]string{}, templates: map[uint32]*template{}}
		free := int(le.Uint32(buf[48:]))
		if free < 512 || free > chunkSize {
			free = chunkSize
		}
		for pos := 512; pos+28 <= free; {
			if le.Uint32(buf[pos:]) != 0x00002A2A {
				break
			}
			n := int(le.Uint32(buf[pos+4:]))
			if n < 28 || pos+n > chunkSize {
				st.BadRecords++
				break
			}
			st.Records++
			e, err := c.record(pos, n)
			if err != nil {
				st.BadRecords++
			} else if err := fn(e); err != nil {
				return st, err
			}
			pos += n
		}
	}
	return st, nil
}

type chunk struct {
	b         []byte
	names     map[uint32]string
	templates map[uint32]*template
}

func (c *chunk) record(pos, n int) (Event, error) {
	e := Event{RecordID: le.Uint64(c.b[pos+8:])}
	p := &reader{c: c, pos: pos + 24, end: pos + n - 4}
	root, err := p.document(nil, 0)
	if err != nil {
		return e, err
	}
	ev := root.child("Event")
	if ev == nil {
		return e, errors.New("no Event element")
	}
	e.System = map[string]string{}
	if sys := ev.child("System"); sys != nil {
		for _, k := range sys.kids {
			switch k.name {
			case "Provider":
				e.System["Provider"] = k.attr("Name")
				if e.System["Provider"] == "" {
					e.System["Provider"] = k.attr("EventSourceName")
				}
			case "EventID":
				e.System["EventID"] = k.text
				e.System["Qualifiers"] = k.attr("Qualifiers")
			case "TimeCreated":
				e.System["TimeCreated"] = k.attr("SystemTime")
			case "Correlation":
				e.System["ActivityID"] = k.attr("ActivityID")
			case "Execution":
				e.System["ProcessID"], e.System["ThreadID"] = k.attr("ProcessID"), k.attr("ThreadID")
			case "Security":
				e.System["UserID"] = k.attr("UserID")
			default:
				e.System[k.name] = k.text
			}
		}
	}
	if d := ev.child("EventData"); d != nil {
		for i, k := range d.kids {
			name := k.attr("Name")
			if name == "" {
				name = fmt.Sprintf("%s%d", k.name, i+1)
			}
			e.Data = append(e.Data, Field{name, k.flat()})
		}
	}
	if u := ev.child("UserData"); u != nil {
		for _, top := range u.kids {
			for _, k := range top.kids {
				e.Data = append(e.Data, Field{k.name, k.flat()})
			}
		}
	}
	return e, nil
}

// node is a rendered element.
type node struct {
	name  string
	attrs [][2]string
	text  string
	kids  []*node
}

func (n *node) child(name string) *node {
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func (n *node) attr(name string) string {
	for _, a := range n.attrs {
		if a[0] == name {
			return a[1]
		}
	}
	return ""
}

// flat is an element's text, or its children's as Name=value pairs.
func (n *node) flat() string {
	if len(n.kids) == 0 {
		return n.text
	}
	var parts []string
	for _, k := range n.kids {
		parts = append(parts, k.name+"="+k.flat())
	}
	return strings.Join(parts, "; ")
}

// FileTime converts a FILETIME; zero and out-of-range values are zero.
func FileTime(v uint64) time.Time {
	const epoch = 116444736000000000
	if v <= epoch || v > epoch+uint64(400*365*24*3600)*10_000_000 {
		return time.Time{}
	}
	return time.Unix(0, int64(v-epoch)*100).UTC()
}
