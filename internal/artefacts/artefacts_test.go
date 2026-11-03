package artefacts

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// tableOf finds a table in a manifest.
func tableOf(m Manifest, name string) TableInfo {
	for _, t := range m.Tables {
		if t.Name == name {
			return t
		}
	}
	return TableInfo{}
}

// The test binary doubles as the parsing process.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == ChildArg {
		os.Exit(ChildMain(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}

var when = time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)

// pf builds a minimal version 17 prefetch file.
func pf(exe string, runs uint32) []byte {
	le := binary.LittleEndian
	b := make([]byte, 0x200)
	le.PutUint32(b, 17)
	copy(b[4:], "SCCA")
	for i, c := range utf16.Encode([]rune(exe)) {
		le.PutUint16(b[16+2*i:], c)
	}
	le.PutUint64(b[120:], uint64(when.UnixNano()/100)+116444736000000000)
	le.PutUint32(b[144:], runs)
	return b
}

// pkg writes a triage package with the given entries.
func pkg(t *testing.T, entries map[string][]byte) string {
	path := filepath.Join(t.TempDir(), "triage.zip")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	zw := zip.NewWriter(f)
	for name, b := range entries {
		w, _ := zw.Create(name)
		w.Write(b)
	}
	zw.Close()
	f.Close()
	return path
}

func request(t *testing.T, input string) Request {
	dir := t.TempDir()
	return Request{Input: input, Source: "triage", Output: filepath.Join(dir, "out.zip"), Temp: dir, MaxOutput: 1 << 30}
}

func readTable(t *testing.T, path, name string) []byte {
	zr, e := zip.OpenReader(path)
	if e != nil {
		t.Fatal(e)
	}
	defer zr.Close()
	f, e := zr.Open("tables/" + name + ".csv")
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestParseTriagePackage(t *testing.T) {
	in := pkg(t, map[string][]byte{
		"C/Windows/Prefetch/CMD.EXE-0BD30981.pf":     pf("CMD.EXE", 7),
		"C/Windows/Prefetch/BROKEN.EXE-00000000.pf":  []byte("not a prefetch file"),
		"C/Windows/System32/config/SOFTWARE":         []byte("x"),
		"C/Users/a/AppData/Roaming/notes.pf":         pf("NOPE.EXE", 1),
		"manifest.json":                              []byte("{}"),
		"C/Windows/Prefetch/NOTEPAD.EXE-12345678.pf": pf("NOTEPAD.EXE", 3),
	})
	req := request(t, in)
	m, e := Parse(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	if pf := tableOf(m, "prefetch"); m.Format != Format || m.Parser != ParserVersion || len(m.Tables) != 2 || m.Tables[0].Name != "timeline" || pf.Rows != 2 || pf.Sources != 2 {
		t.Fatalf("%+v", m)
	}
	// The broken prefetch file and the placeholder SOFTWARE hive.
	if len(m.Errors) != 2 || m.Errors[0].Path != `C:\Windows\Prefetch\BROKEN.EXE-00000000.pf` && m.Errors[1].Path != `C:\Windows\Prefetch\BROKEN.EXE-00000000.pf` {
		t.Fatalf("errors %+v", m.Errors)
	}
	table := string(readTable(t, req.Output, "prefetch"))
	if !strings.HasPrefix(table, "SourceFile,Executable,") || !strings.Contains(table, `C:\Windows\Prefetch\CMD.EXE-0BD30981.pf,CMD.EXE,,00000000,17,7,2026-11-03 09:30:00.0000000,`) {
		t.Fatal(table)
	}
	// The viewer pages through it with filters.
	p, e := Query(bytes.NewReader([]byte(table)), prefetchTable.Times, Filter{Contains: "notepad"}, 0, 10)
	if e != nil || len(p.Rows) != 1 || p.Rows[0][1] != "NOTEPAD.EXE" || p.More {
		t.Fatal(p, e)
	}
	p, _ = Query(bytes.NewReader([]byte(table)), prefetchTable.Times, Filter{From: "2026-11-04 00:00:00.0000000"}, 0, 10)
	if len(p.Rows) != 0 {
		t.Fatal("time filter", p)
	}
	p, _ = Query(bytes.NewReader([]byte(table)), prefetchTable.Times, Filter{}, 1, 1)
	if len(p.Rows) != 1 || p.More || p.Offset != 1 {
		t.Fatal("paging", p)
	}
	// The manifest is in the results.
	zr, _ := zip.OpenReader(req.Output)
	defer zr.Close()
	mf, _ := zr.Open("manifest.json")
	var back Manifest
	if json.NewDecoder(mf).Decode(&back) != nil || back.Tables[0].Rows != 2 {
		t.Fatal("manifest", back)
	}
}

func TestParseInChildProcess(t *testing.T) {
	exe, _ := os.Executable()
	in := pkg(t, map[string][]byte{"C/Windows/Prefetch/CMD.EXE-0BD30981.pf": pf("CMD.EXE", 7)})
	req := request(t, in)
	m, outcome := Run(context.Background(), exe, req)
	if outcome != "" || tableOf(m, "prefetch").Rows != 1 {
		t.Fatal(m, outcome)
	}
	// Not a package.
	bad := filepath.Join(t.TempDir(), "bad.zip")
	os.WriteFile(bad, []byte("nope"), 0600)
	if _, outcome := Run(context.Background(), exe, request(t, bad)); outcome != OutcomeUnreadable {
		t.Fatal(outcome)
	}
	// Results beyond their limit.
	req = request(t, in)
	req.MaxOutput = 10
	if _, outcome := Run(context.Background(), exe, req); outcome != OutcomeOutputLimit {
		t.Fatal(outcome)
	}
	// Out of time.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, outcome := Run(ctx, exe, request(t, in)); outcome != OutcomeTimeLimit {
		t.Fatal(outcome)
	}
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0600) }
