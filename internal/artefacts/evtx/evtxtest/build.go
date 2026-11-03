// Package evtxtest builds event log files for tests: one chunk of
// Security logon-style records from a single template.
package evtxtest

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// When is every record's time.
var When = time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)

const (
	headerSize = 4096
	chunkSize  = 65536
)

// chunkBuilder writes binary XML into a chunk, defining every name inline.
type chunkBuilder struct{ b []byte }

func (c *chunkBuilder) u8(v byte)    { c.b = append(c.b, v) }
func (c *chunkBuilder) u16(v uint16) { c.b = binary.LittleEndian.AppendUint16(c.b, v) }
func (c *chunkBuilder) u32(v uint32) { c.b = binary.LittleEndian.AppendUint32(c.b, v) }

func (c *chunkBuilder) name(s string) {
	u := utf16.Encode([]rune(s))
	c.u32(uint32(len(c.b) + 4)) // defined right here
	c.u32(0)
	c.u16(0)
	c.u16(uint16(len(u)))
	for _, r := range u {
		c.u16(r)
	}
	c.u16(0)
}

func (c *chunkBuilder) open(name string, attrs bool) {
	if attrs {
		c.u8(0x41)
	} else {
		c.u8(0x01)
	}
	c.u16(0xFFFF)
	c.u32(0)
	c.name(name)
	if attrs {
		c.u32(0)
	}
}

func (c *chunkBuilder) sub(id uint16, typ byte) { c.u8(0x0D); c.u16(id); c.u8(typ) }

// element with one substituted attribute or substituted text.
func (c *chunkBuilder) attrElem(name, attr string, id uint16, typ byte) {
	c.open(name, true)
	c.u8(0x06)
	c.name(attr)
	c.sub(id, typ)
	c.u8(0x03)
}

func (c *chunkBuilder) textElem(name string, id uint16, typ byte) {
	c.open(name, false)
	c.u8(0x02)
	c.sub(id, typ)
	c.u8(0x04)
}

func (c *chunkBuilder) data(name string, id uint16, typ byte) {
	c.open("Data", true)
	c.u8(0x06)
	c.name("Name")
	c.u8(0x05)
	c.u8(0x01)
	u := utf16.Encode([]rune(name))
	c.u16(uint16(len(u)))
	for _, r := range u {
		c.u16(r)
	}
	c.u8(0x02)
	c.sub(id, typ)
	c.u8(0x04)
}

func u16(s string) []byte {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, r)
	}
	return b
}

// record appends an event record whose template is defined in it when
// tmpl is 0, else referenced at tmpl. It returns the template's offset.
func (c *chunkBuilder) record(id uint64, tmpl uint32, user string, logon uint32) uint32 {
	start := len(c.b)
	c.u32(0x00002A2A)
	c.u32(0)
	c.b = binary.LittleEndian.AppendUint64(c.b, id)
	c.b = binary.LittleEndian.AppendUint64(c.b, 0)
	c.u8(0x0F)
	c.u8(1)
	c.u8(1)
	c.u8(0)
	c.u8(0x0C)
	c.u8(1)
	c.u32(7)
	if tmpl == 0 {
		tmpl = uint32(len(c.b) + 4)
		c.u32(tmpl)
		c.u32(0)
		c.b = append(c.b, make([]byte, 16)...)
		sizeAt := len(c.b)
		c.u32(0)
		body := len(c.b)
		c.u8(0x0F)
		c.u8(1)
		c.u8(1)
		c.u8(0)
		c.open("Event", false)
		c.u8(0x02)
		c.open("System", false)
		c.u8(0x02)
		c.attrElem("Provider", "Name", 0, 0x01)
		c.textElem("EventID", 1, 0x06)
		c.textElem("Level", 2, 0x04)
		c.attrElem("TimeCreated", "SystemTime", 3, 0x11)
		c.textElem("EventRecordID", 4, 0x0A)
		c.textElem("Channel", 5, 0x01)
		c.textElem("Computer", 6, 0x01)
		c.attrElem("Security", "UserID", 7, 0x13)
		c.u8(0x04)
		c.open("EventData", false)
		c.u8(0x02)
		c.data("TargetUserName", 8, 0x01)
		c.data("LogonType", 9, 0x08)
		c.u8(0x04)
		c.u8(0x04)
		c.u8(0x00)
		binary.LittleEndian.PutUint32(c.b[sizeAt:], uint32(len(c.b)-body))
	} else {
		c.u32(tmpl)
	}
	sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0}
	values := [][]byte{u16("Microsoft-Windows-Security-Auditing"), {0x40, 0x12}, {0}, binary.LittleEndian.AppendUint64(nil, uint64(When.UnixNano()/100)+116444736000000000),
		binary.LittleEndian.AppendUint64(nil, id), u16("Security"), u16("PC-1"), sid, u16(user), binary.LittleEndian.AppendUint32(nil, logon)}
	types := []byte{0x01, 0x06, 0x04, 0x11, 0x0A, 0x01, 0x01, 0x13, 0x01, 0x08}
	c.u32(uint32(len(values)))
	for i, v := range values {
		c.u16(uint16(len(v)))
		c.u8(types[i])
		c.u8(0)
	}
	for _, v := range values {
		c.b = append(c.b, v...)
	}
	c.u8(0x00)
	n := len(c.b) - start + 4
	binary.LittleEndian.PutUint32(c.b[start+4:], uint32(n))
	c.u32(uint32(n))
	return tmpl
}

// Log builds an event log with one record per user: event 4672 from
// computer PC-1, TargetUserName the user and LogonType 2, 10, 18, ...
func Log(users ...string) []byte {
	c := &chunkBuilder{b: make([]byte, 512)}
	copy(c.b, "ElfChnk\x00")
	var tmpl uint32
	for i, u := range users {
		tmpl = c.record(uint64(i+1), tmpl, u, uint32(2+8*i))
	}
	binary.LittleEndian.PutUint32(c.b[48:], uint32(len(c.b)))
	chunk := append(c.b, make([]byte, chunkSize-len(c.b))...)
	head := make([]byte, headerSize)
	copy(head, "ElfFile\x00")
	return append(head, chunk...)
}
