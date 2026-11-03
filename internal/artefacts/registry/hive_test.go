package registry

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/registry/registrytest"
)

var when = time.Date(2026, 11, 3, 9, 30, 0, 0, time.UTC)

func sample(extra string) *registrytest.Key {
	run := &registrytest.Key{Name: "Run", Time: when, Values: []registrytest.Value{
		{Name: "Updater", Type: String, Data: registrytest.U16(`C:\Program Files\U\u.exe /quiet`)},
		{Name: "Count", Type: DWord, Data: registrytest.DWord(7)},
		{Name: "Multi", Type: MultiString, Data: append(append(registrytest.U16("a"), registrytest.U16("b")...), 0, 0)},
		{Name: "Big", Type: Binary, Data: bytes.Repeat([]byte{0xAB}, 40000)},
	}}
	if extra != "" {
		run.Values = append(run.Values, registrytest.Value{Name: extra, Type: String, Data: registrytest.U16("new")})
	}
	return &registrytest.Key{Name: "ROOT", Time: when, Subkeys: []*registrytest.Key{
		{Name: "Software", Time: when.Add(-time.Hour), Subkeys: []*registrytest.Key{{Name: "Microsoft", Time: when, Subkeys: []*registrytest.Key{run}}}},
		{Name: "Empty", Time: when},
	}}
}

func TestKeysAndValues(t *testing.T) {
	h, err := Open(registrytest.Hive(sample(""), when))
	if err != nil {
		t.Fatal(err)
	}
	if h.Dirty || !h.LastWritten.Equal(when) {
		t.Fatal(h.Dirty, h.LastWritten)
	}
	root, _ := h.Root()
	run, ok := root.Subkey(`software\MICROSOFT\Run`)
	if !ok || run.Name() != "Run" || !run.LastWrite().Equal(when) {
		t.Fatal("subkey", ok)
	}
	v, ok := run.Value("updater")
	if !ok || v.Text() != `C:\Program Files\U\u.exe /quiet` {
		t.Fatal("string", v.Text())
	}
	if v, _ := run.Value("Count"); v.Text() != "7" {
		t.Fatal("dword", v.Text())
	}
	if n, ok := mustValue(run, "Count").Uint(); !ok || n != 7 {
		t.Fatal("uint")
	}
	if v, _ := run.Value("Multi"); v.Text() != "a|b" {
		t.Fatal("multi", v.Text())
	}
	d, err := mustValue(run, "Big").Data()
	if err != nil || len(d) != 40000 || d[39999] != 0xAB {
		t.Fatal("segmented data", len(d), err)
	}
	if _, ok := root.Subkey(`Software\Nope`); ok {
		t.Fatal("missing key found")
	}
}

func mustValue(k Key, name string) Value {
	v, _ := k.Value(name)
	return v
}

// A dirty hive is brought up to date from its logs: entries continuing
// its sequence apply, others (damaged, out of sequence) do not.
func TestReplay(t *testing.T) {
	old := registrytest.Hive(sample(""), when)
	newer := registrytest.Hive(sample("Added"), when.Add(time.Minute))
	log := registrytest.Log(old, newer, 5)
	dirty := func() []byte {
		b := append([]byte(nil), old...)
		binary.LittleEndian.PutUint32(b[4:], 6) // primary 6, secondary 5
		return b
	}
	h, err := Open(dirty(), log)
	if err != nil || !h.Dirty || h.Replayed != 1 {
		t.Fatal(err, h)
	}
	root, _ := h.Root()
	run, _ := root.Subkey(`Software\Microsoft\Run`)
	if v, ok := run.Value("Added"); !ok || v.Text() != "new" {
		t.Fatal("log entry not applied")
	}
	// The same entry in both logs applies once.
	if h, _ := Open(dirty(), log, log); h.Replayed != 1 {
		t.Fatal("applied twice", h.Replayed)
	}
	// A damaged entry is not applied.
	bad := append([]byte(nil), log...)
	bad[len(bad)-100] ^= 1
	if h, _ := Open(dirty(), bad); h.Replayed != 0 {
		t.Fatal("damaged entry applied")
	}
	// An entry before the hive's last write is old.
	if h, _ := Open(dirty(), registrytest.Log(old, newer, 4)); h.Replayed != 0 {
		t.Fatal("old entry applied")
	}
	// A clean hive ignores its logs.
	if h, _ := Open(append([]byte(nil), old...), log); h.Dirty || h.Replayed != 0 {
		t.Fatal("clean hive replayed")
	}
}

// Damaged input never panics; walks stay bounded.
func TestDamagedHive(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	good := registrytest.Hive(sample(""), when)
	for range 2000 {
		b := append([]byte(nil), good...)
		for range 1 + r.IntN(30) {
			b[4096+r.IntN(len(b)-4096)] = byte(r.Uint32())
		}
		if r.IntN(4) == 0 {
			b = b[:4096+r.IntN(len(b)-4096)]
		}
		h, err := Open(b)
		if err != nil {
			continue
		}
		walk(t, h)
	}
}

func walk(t *testing.T, h *Hive) {
	root, err := h.Root()
	if err != nil {
		return
	}
	n := 0
	var visit func(k Key, depth int)
	visit = func(k Key, depth int) {
		if n++; n > 10000 || depth > 64 {
			return
		}
		_ = k.Name() + k.LastWrite().String()
		values, _ := k.Values()
		for _, v := range values {
			_ = v.Name() + v.Text()
		}
		subs, _ := k.Subkeys()
		for _, s := range subs {
			visit(s, depth+1)
		}
	}
	visit(root, 0)
	_ = strings.ToLower
}
