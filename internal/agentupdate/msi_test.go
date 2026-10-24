package agentupdate

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func msiManifest(hash string, size int64) protocol.AgentManifest {
	return protocol.AgentManifest{Format: 2, Package: "msi", AgentHash: strings.Repeat("a", 64), Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "1.0", Sequence: 7, Size: size, Hash: hash, KeyID: strings.Repeat("b", 64), Issued: 1, Expires: 2}
}

func TestMSIManifestFormat(t *testing.T) {
	m := msiManifest(strings.Repeat("c", 64), 10)
	if !Valid(m) || !MSI(m) || AgentHash(m) != m.AgentHash {
		t.Fatal("valid MSI manifest refused")
	}
	for _, mutate := range []func(*protocol.AgentManifest){
		func(m *protocol.AgentManifest) { m.Package = "exe" },
		func(m *protocol.AgentManifest) { m.AgentHash = "" },
		func(m *protocol.AgentManifest) { m.Format = 1 }, // format 1 carries no package fields
		func(m *protocol.AgentManifest) { m.Sequence = MaxMSISequence + 1 },
	} {
		x := msiManifest(m.Hash, m.Size)
		mutate(&x)
		if Valid(x) {
			t.Fatal("invalid MSI manifest accepted", x)
		}
	}
	old := m
	old.Format, old.Package, old.AgentHash = 1, "", ""
	if !Valid(old) || MSI(old) || AgentHash(old) != old.Hash {
		t.Fatal("format 1 behaviour changed")
	}
}

func TestInspectChecksMSIContainer(t *testing.T) {
	dir := t.TempDir()
	good := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, []byte("rest of a package")...)
	path := filepath.Join(dir, "a.msi")
	if e := os.WriteFile(path, good, 0600); e != nil {
		t.Fatal(e)
	}
	if Inspect(path, msiManifest(Digest(good), int64(len(good)))) != nil {
		t.Fatal("MSI container refused")
	}
	bad := append([]byte("MZ"), good[2:]...)
	if e := os.WriteFile(path, bad, 0600); e != nil {
		t.Fatal(e)
	}
	if Inspect(path, msiManifest(Digest(bad), int64(len(bad)))) == nil {
		t.Fatal("non-MSI accepted as an MSI release")
	}
}

func TestBuiltInTrustAndJournalSupport(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	key := hex.EncodeToString(pub)
	defer func(k, s string) { PinnedKeys, ReleaseSequence = k, s }(PinnedKeys, ReleaseSequence)
	PinnedKeys, ReleaseSequence = " "+key+",not-a-key,"+key, "42"
	if got := Keys(); len(got) != 1 || got[0] != key || SequenceFloor() != 42 {
		t.Fatal("pinned keys or sequence floor", got, SequenceFloor())
	}
	ReleaseSequence = "4x"
	if SequenceFloor() != 0 {
		t.Fatal("malformed sequence accepted")
	}
	path := filepath.Join(t.TempDir(), "journal.json")
	if s := JournalSupport(path); s.Broker != "recovery_required" || s.Installer != "msi" {
		t.Fatal("missing journal with keys", s)
	}
	current := strings.Repeat("d", 64)
	if e := SaveJSON(path, Journal{Format: 1, Current: current, HighWater: 9, Records: []Record{}}); e != nil {
		t.Fatal(e)
	}
	s := JournalSupport(path)
	if s.Broker != "enabled" || s.CurrentHash != current || s.HighWater != 9 || len(s.KeyIDs) != 1 || !SupportValid(s) {
		t.Fatal("idle journal support", s)
	}
	PinnedKeys = ""
	if s = JournalSupport(path); s.Broker != "disabled" || len(s.KeyIDs) != 0 {
		t.Fatal("build without keys must not accept updates", s)
	}
	if r, e := JournalStatus(path, strings.Repeat("e", 32)); e != nil || r.Outcome != "unknown" {
		t.Fatal("unknown job status", r, e)
	}
}
