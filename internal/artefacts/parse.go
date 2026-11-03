package artefacts

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"strings"
)

// Request is what the server hands a parsing process.
type Request struct {
	Input string `json:"input"`
	// Source is the collection's source: triage (a package), hive or evtx
	// (a single file, Name being its path on the device).
	Source    string `json:"source"`
	Name      string `json:"name"`
	Output    string `json:"output"`
	Temp      string `json:"temp"`
	MaxOutput int64  `json:"max_output"`
}

// Parseable reports whether collections of a source are parsed.
func Parseable(source string) bool {
	return source == "triage" || source == "hive" || source == "evtx"
}

// ErrUnreadable reports a collection that is not what its source says.
var ErrUnreadable = errors.New("the collection cannot be read")

// file is one collected file: its path on the device and its contents.
type file struct {
	path string
	size int64
	open func() (io.ReadCloser, error)
	// sibling finds another file of the same collection by its path.
	sibling func(path string) (file, bool)
}

// parser handles the files it matches, up to max bytes each: by the
// collection's source and the file's lower-case path (for a single-file
// collection its name, such as "system", "ntuser:alice" or a channel).
type parser struct {
	table string
	match func(source, path string) bool
	max   int64
	parse func(ctx context.Context, o *Output, f file) error
}

var parsers = []parser{prefetchParser, registryParser, eventLogParser}

// Parse reads a collection and writes the parsed results to req.Output.
func Parse(ctx context.Context, req Request) (Manifest, error) {
	out, e := os.OpenFile(req.Output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return Manifest{}, e
	}
	defer out.Close()
	o := NewOutput(req.Temp, req.Source, req.MaxOutput)
	defer o.Close()
	each := func(f file) error {
		lower := strings.ToLower(f.path)
		for _, p := range parsers {
			if !p.match(req.Source, lower) {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if f.size > p.max {
				o.Fail(f.path, p.table, errors.New("the file is larger than this parser reads"))
				continue
			}
			if e := p.parse(ctx, o, f); errors.Is(e, ErrOutputLimit) || ctx.Err() != nil {
				return e
			} else if e != nil {
				o.Fail(f.path, p.table, e)
			}
		}
		return nil
	}
	if req.Source == "triage" {
		zr, e := zip.OpenReader(req.Input)
		if e != nil {
			return Manifest{}, ErrUnreadable
		}
		defer zr.Close()
		byPath := map[string]*zip.File{}
		for _, z := range zr.File {
			if path, ok := devicePath(z.Name); ok && !z.FileInfo().IsDir() {
				byPath[strings.ToLower(path)] = z
			}
		}
		var sibling func(string) (file, bool)
		entry := func(path string, z *zip.File) file {
			return file{path: path, size: int64(z.UncompressedSize64), open: z.Open, sibling: sibling}
		}
		sibling = func(path string) (file, bool) {
			z, ok := byPath[strings.ToLower(path)]
			if !ok {
				return file{}, false
			}
			return entry(path, z), true
		}
		for _, z := range zr.File {
			path, ok := devicePath(z.Name)
			if !ok || z.FileInfo().IsDir() {
				continue
			}
			if e := each(entry(path, z)); e != nil {
				return Manifest{}, e
			}
		}
	} else {
		i, e := os.Stat(req.Input)
		if e != nil {
			return Manifest{}, ErrUnreadable
		}
		input := req.Input
		none := func(string) (file, bool) { return file{}, false }
		if e := each(file{path: req.Name, size: i.Size(), open: func() (io.ReadCloser, error) { return os.Open(input) }, sibling: none}); e != nil {
			return Manifest{}, e
		}
	}
	return o.Finish(out)
}

// devicePath turns a triage package entry (C/Windows/x.pf) into the file's
// path on the device (C:\Windows\x.pf).
func devicePath(name string) (string, bool) {
	if len(name) < 3 || name[1] != '/' || name[0] < 'A' || name[0] > 'Z' {
		return "", false
	}
	return name[:1] + `:\` + strings.ReplaceAll(name[2:], "/", `\`), true
}

// readAll reads a file of at most max bytes into memory.
func readAll(f file, max int64) ([]byte, error) {
	r, e := f.open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > max {
		return nil, errors.New("the file is larger than this parser reads")
	}
	return b, nil
}
