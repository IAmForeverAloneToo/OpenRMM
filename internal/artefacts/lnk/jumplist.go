package lnk

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// Entry is one item of a jump list: the shortcut and, for automatic jump
// lists, what the DestList records about it.
type Entry struct {
	Link
	// Stream is the entry's stream (automatic) or position (custom).
	Stream      string
	Path        string
	LastAccess  time.Time
	Pinned      bool
	AccessCount uint32
	Hostname    string
	// Err is set when the entry's shortcut did not decode.
	Err error
}

// Automatic reads an automatic jump list (.automaticDestinations-ms): an
// OLE compound file of numbered shortcut streams and a DestList.
func Automatic(b []byte) ([]Entry, error) {
	f, err := openCFB(b)
	if err != nil {
		return nil, err
	}
	streams := f.streams()
	byNumber := map[string]*Entry{}
	var out []Entry
	for _, s := range streams {
		if s.name == "DestList" {
			continue
		}
		if _, err := strconv.ParseUint(s.name, 16, 64); err != nil {
			continue
		}
		data, err := f.read(s)
		e := Entry{Stream: s.name}
		if err == nil {
			e.Link, e.Err = Parse(data)
		} else {
			e.Err = err
		}
		out = append(out, e)
	}
	for i := range out {
		byNumber[strings.ToLower(out[i].Stream)] = &out[i]
	}
	for _, s := range streams {
		if s.name != "DestList" {
			continue
		}
		data, err := f.read(s)
		if err != nil {
			break
		}
		for _, d := range destList(data) {
			if e, ok := byNumber[d.Stream]; ok {
				e.Path, e.LastAccess, e.Pinned, e.AccessCount, e.Hostname = d.Path, d.LastAccess, d.Pinned, d.AccessCount, d.Hostname
			} else {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// destList decodes the DestList stream: a 32-byte header, then entries of
// 114 bytes (version 1, Windows 7 and 8) or 130 bytes (later) before the
// path, which later versions follow with 4 more bytes.
func destList(d []byte) []Entry {
	if len(d) < 32 {
		return nil
	}
	version := le.Uint32(d)
	head, tail := 130, 4
	if version < 2 {
		head, tail = 114, 0
	}
	var out []Entry
	for pos := 32; pos+head <= len(d) && len(out) < 100_000; {
		e := d[pos:]
		n := 2 * int(le.Uint16(e[head-2:]))
		if pos+head+n+tail > len(d) {
			break
		}
		entry := Entry{
			Stream:     strings.ToLower(strconv.FormatUint(uint64(le.Uint32(e[88:])), 16)),
			Hostname:   cstring(e[72:88]),
			LastAccess: filetime(le.Uint64(e[100:])),
			Pinned:     int32(le.Uint32(e[108:])) >= 0,
			Path:       utf16s(e[head : head+n]),
		}
		if version >= 2 {
			entry.AccessCount = le.Uint32(e[116:])
		}
		out = append(out, entry)
		pos += head + n + tail
	}
	return out
}

// Custom reads a custom jump list (.customDestinations-ms): shortcuts
// stored one after another, found by their header.
func Custom(b []byte) []Entry {
	var out []Entry
	for pos := 0; pos < len(b) && len(out) < 10_000; {
		i := bytes.Index(b[pos:], Header)
		if i < 0 {
			break
		}
		at := pos + i
		l, err := Parse(b[at:])
		out = append(out, Entry{Link: l, Stream: strconv.Itoa(len(out) + 1), Err: err})
		pos = at + len(Header)
	}
	return out
}
