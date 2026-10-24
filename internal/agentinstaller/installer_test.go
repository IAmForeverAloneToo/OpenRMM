package agentinstaller

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func TestInstallerZipHoldsUnchangedMSIAndSetup(t *testing.T) {
	msi := bytes.Repeat([]byte("msi"), 1000)
	release := protocol.SignedAgentRelease{Manifest: protocol.AgentManifest{Format: 2, Package: "msi", Version: "1.2.3", Sequence: 16}, Signature: "sig"}
	enrollment := protocol.EnrollmentFile{Version: 1, ServerURL: "https://rmm.example.com:8443", DeviceURL: "https://rmm.example.com:8444", Token: "token"}
	var out bytes.Buffer
	if err := Write(&out, bytes.NewReader(msi), int64(len(msi)), release, enrollment, time.Unix(1800000000, 0)); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		files[f.Name] = b
		if f.Name == "openrmm-agent.msi" && f.Method != zip.Store {
			t.Fatal("MSI recompressed")
		}
	}
	if len(files) != 6 || !bytes.Equal(files["openrmm-agent.msi"], msi) {
		t.Fatal("ZIP contents", len(files))
	}
	for _, name := range Scripts {
		s := string(files[name])
		if s == "" || strings.Count(s, "\n") != strings.Count(s, "\r\n") {
			t.Fatal("setup file missing or without CRLF line endings", name)
		}
	}
	var e protocol.EnrollmentFile
	if json.Unmarshal(files["enrollment.json"], &e) != nil || e != enrollment {
		t.Fatal("enrollment file", e)
	}
	var r protocol.SignedAgentRelease
	if json.Unmarshal(files["release.json"], &r) != nil || r != release {
		t.Fatal("release file", r)
	}
	if err := Write(io.Discard, bytes.NewReader(msi[:10]), int64(len(msi)), release, enrollment, time.Now()); err == nil {
		t.Fatal("short MSI accepted")
	}
}
