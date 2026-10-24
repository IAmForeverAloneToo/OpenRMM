package agentbundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"testing/fstest"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func fixture(t *testing.T) fstest.MapFS {
	t.Helper()
	artifact := make([]byte, 64+4+20+240)
	copy(artifact, "MZ")
	binary.LittleEndian.PutUint32(artifact[60:], 64)
	copy(artifact[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(artifact[68:], 0x8664)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.2", Sequence: 9, Size: int64(len(artifact)), Hash: agentupdate.Digest(artifact), KeyID: agentupdate.Digest(public), Issued: now.Unix(), Expires: now.Add(time.Hour).Unix()}
	raw, _ := json.Marshal(protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, agentupdate.Message(m)))})
	return fstest.MapFS{
		"files/release.json":      {Data: raw},
		"files/public.txt":        {Data: []byte(hex.EncodeToString(public) + "\n")},
		"files/openrmm-agent.exe": {Data: artifact},
	}
}

func TestLoadBundle(t *testing.T) {
	if _, ok, e := load(fstest.MapFS{"files/README.md": {Data: []byte("none")}}); ok || e != nil {
		t.Fatal("empty bundle reported", ok, e)
	}
	b, ok, e := load(fixture(t))
	if !ok || e != nil || b.Release.Manifest.Sequence != 9 || len(b.PublicKey) != 64 {
		t.Fatal("valid bundle refused", ok, e)
	}
	tampered := fixture(t)
	tampered["files/openrmm-agent.exe"].Data[0] = 'X'
	if _, ok, e = load(tampered); !ok || e == nil {
		t.Fatal("tampered binary accepted")
	}
	missing := fixture(t)
	delete(missing, "files/public.txt")
	if _, ok, e = load(missing); !ok || e == nil {
		t.Fatal("incomplete bundle accepted")
	}
	// The real embedded folder must load (empty in source control).
	if _, _, e = Load(); e != nil {
		t.Fatal("embedded bundle invalid", e)
	}
}
