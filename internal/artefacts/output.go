// Package artefacts parses Windows artefacts from collected evidence
// (triage packages, registry hives, event logs) into tables, on the server
// in a separate process with limits. Results are a ZIP of CSV tables and a
// manifest, read back page by page by the viewer.
package artefacts

import (
	"archive/zip"
	"bufio"
	"compress/flate"
	"encoding/csv"
	"encoding/json"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"time"
)

// Format names the parsed results' manifest; ParserVersion grows when a
// parser changes what it produces, so older results can be parsed again.
const (
	Format        = "openrmm-artefacts"
	ParserVersion = 1
)

// ErrOutputLimit stops a parse whose results would pass their size limit.
var ErrOutputLimit = errors.New("the parsed results reached their size limit")

// TimeLayout is the format of every time in a table (UTC); it sorts as text.
const TimeLayout = "2006-01-02 15:04:05.0000000"

// Stamp formats a time for a table ("" for the zero time).
func Stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(TimeLayout)
}

// Def describes a table: its columns, and those holding times (a cell may
// hold several, separated by "|"), which the viewer's time filter checks.
type Def struct {
	Name    string
	Title   string
	Columns []string
	Times   []string
}

// TableInfo describes one table in the manifest.
type TableInfo struct {
	Name    string   `json:"name"`
	Title   string   `json:"title"`
	Columns []string `json:"columns"`
	Times   []string `json:"times"`
	Rows    int64    `json:"rows"`
	// Sources counts the files the table's rows came from.
	Sources int `json:"sources"`
}

// FileError is a file that could not be parsed.
type FileError struct {
	Path  string `json:"path"`
	Table string `json:"table"`
	Error string `json:"error"`
}

// Manifest describes parsed results.
type Manifest struct {
	Format  string      `json:"format"`
	Version int         `json:"version"`
	Parser  int         `json:"parser"`
	Source  string      `json:"source"`
	Tables  []TableInfo `json:"tables"`
	Errors  []FileError `json:"errors"`
	// ErrorsMore counts errors past the listed 1,000.
	ErrorsMore int `json:"errors_more,omitempty"`
}

const maxErrors = 1000

// Output collects rows into compressed temporary files, one per table, and
// counts the compressed bytes against a limit.
type Output struct {
	dir    string
	left   int64
	tables map[string]*table
	order  []string
	m      Manifest
}

type table struct {
	info    TableInfo
	f       *os.File
	buf     *bufio.Writer
	z       *flate.Writer
	crc     hash.Hash32
	size    int64
	csv     *csv.Writer
	sources map[string]bool
}

// NewOutput writes temporary files into dir, at most limit compressed bytes.
func NewOutput(dir, source string, limit int64) *Output {
	return &Output{dir: dir, left: limit, tables: map[string]*table{}, m: Manifest{Format: Format, Version: 1, Parser: ParserVersion, Source: source, Tables: []TableInfo{}, Errors: []FileError{}}}
}

// counter counts compressed bytes against the output's limit.
type counter struct {
	w io.Writer
	o *Output
}

func (c counter) Write(p []byte) (int, error) {
	if c.o.left -= int64(len(p)); c.o.left < 0 {
		return 0, ErrOutputLimit
	}
	return c.w.Write(p)
}

// tableWriter feeds the CRC and size of the uncompressed CSV.
type tableWriter struct{ t *table }

func (w tableWriter) Write(p []byte) (int, error) {
	w.t.crc.Write(p)
	w.t.size += int64(len(p))
	return w.t.z.Write(p)
}

// Add writes a row of a table from source (the file it came from),
// creating the table with its header on first use.
func (o *Output) Add(d Def, source string, row []string) error {
	t, ok := o.tables[d.Name]
	if !ok {
		f, e := os.CreateTemp(o.dir, "table-*")
		if e != nil {
			return e
		}
		t = &table{info: TableInfo{Name: d.Name, Title: d.Title, Columns: d.Columns, Times: d.Times}, f: f, crc: crc32.NewIEEE(), sources: map[string]bool{}}
		t.buf = bufio.NewWriterSize(counter{f, o}, 1<<16)
		t.z, _ = flate.NewWriter(t.buf, flate.DefaultCompression)
		t.csv = csv.NewWriter(tableWriter{t})
		o.tables[d.Name] = t
		o.order = append(o.order, d.Name)
		if e := t.csv.Write(d.Columns); e != nil {
			return e
		}
	}
	if len(row) != len(t.info.Columns) {
		return errors.New("row width differs from the table's columns")
	}
	t.sources[source] = true
	t.info.Rows++
	if t.info.Rows%4096 == 0 {
		t.csv.Flush()
		if e := t.csv.Error(); e != nil {
			return e
		}
	}
	return t.csv.Write(row)
}

// Fail records a file that could not be parsed.
func (o *Output) Fail(path, table string, err error) {
	if len(o.m.Errors) >= maxErrors {
		o.m.ErrorsMore++
		return
	}
	o.m.Errors = append(o.m.Errors, FileError{Path: path, Table: table, Error: err.Error()})
}

// Close removes the temporary files.
func (o *Output) Close() {
	for _, t := range o.tables {
		t.f.Close()
		os.Remove(t.f.Name())
	}
}

// Finish writes the results to w: tables/<name>.csv for each table, then
// manifest.json. The compressed tables are copied as they are.
func (o *Output) Finish(w io.Writer) (Manifest, error) {
	zw := zip.NewWriter(w)
	for _, name := range o.order {
		t := o.tables[name]
		t.csv.Flush()
		if e := t.csv.Error(); e != nil {
			return Manifest{}, e
		}
		if e := t.z.Close(); e != nil {
			return Manifest{}, e
		}
		if e := t.buf.Flush(); e != nil {
			return Manifest{}, e
		}
		t.info.Sources = len(t.sources)
		o.m.Tables = append(o.m.Tables, t.info)
		if _, e := t.f.Seek(0, io.SeekStart); e != nil {
			return Manifest{}, e
		}
		info, e := t.f.Stat()
		if e != nil {
			return Manifest{}, e
		}
		h := &zip.FileHeader{Name: "tables/" + name + ".csv", Method: zip.Deflate, CRC32: t.crc.Sum32(), CompressedSize64: uint64(info.Size()), UncompressedSize64: uint64(t.size), Modified: time.Now()}
		zf, e := zw.CreateRaw(h)
		if e != nil {
			return Manifest{}, e
		}
		if _, e := io.Copy(zf, t.f); e != nil {
			return Manifest{}, e
		}
	}
	mf, e := zw.Create("manifest.json")
	if e != nil {
		return Manifest{}, e
	}
	if e := json.NewEncoder(mf).Encode(o.m); e != nil {
		return Manifest{}, e
	}
	return o.m, zw.Close()
}
