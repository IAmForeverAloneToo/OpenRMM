package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/ntfs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// An NTFS package is queued from the case page, uploaded by the device as
// usual, and read on the server: manifest, filtered pages and CSV.
func TestNTFSAPI(t *testing.T) {
	f := newAPIFixture(t)
	f.login(t)
	if err := f.store.UseEvidence(t.TempDir(), 0); err != nil {
		t.Fatal(err)
	}
	token, _, e := f.devices.NewToken(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	key, _ := deviceidentity.NewKey()
	csr, _ := deviceidentity.CSR(key)
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: "WS-NTFS", OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	fp, device, now := deviceidentity.Fingerprint(block.Bytes), cred.DeviceID, time.Now()
	if e = f.store.RecordHeartbeat(t.Context(), device, fp, protocol.Heartbeat{Hostname: "WS-NTFS", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityNTFS}}, now); e != nil {
		t.Fatal(e)
	}
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "NTFS"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatal("case", resp.StatusCode)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "ntfs", "volumes": []string{"C:", "C:"}}, true); resp.StatusCode != 400 {
		t.Fatal("repeated volume accepted", resp.StatusCode)
	}
	resp, body = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "ntfs", "volumes": []string{"c:"}}, true)
	var queued struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("collect %d %s", resp.StatusCode, body)
	}
	// The device builds and uploads a package.
	var pkg bytes.Buffer
	zw := zip.NewWriter(&pkg)
	w, _ := zw.Create("C/mft.csv")
	cw, _ := ntfs.NewCSV(w, ntfs.MFTColumns)
	for i, name := range []string{"a.txt", "evil.exe", "b.txt"} {
		row := make([]string, len(ntfs.MFTColumns))
		row[0], row[2], row[5], row[6] = string(rune('0'+i)), "true", `C:\Users`, name
		cw.Write(row)
	}
	cw.Flush()
	w, _ = zw.Create("manifest.json")
	json.NewEncoder(w).Encode(protocol.NTFSManifest{Format: protocol.NTFSFormat, Version: 1, Volumes: []protocol.NTFSVolume{{Volume: "C:", MFTRows: 3}}})
	zw.Close()
	d, e := f.store.DispatchEvidence(t.Context(), device, fp, now)
	if e != nil || d.Job == nil || d.Job.ID != queued.ID || d.Job.Source != "ntfs" || d.Job.Query != "C:" {
		t.Fatalf("dispatch %+v %v", d.Job, e)
	}
	sum := sha256.Sum256(pkg.Bytes())
	if _, e = f.store.StartEvidence(t.Context(), device, fp, queued.ID, protocol.EvidenceStart{Size: int64(pkg.Len()), Resolved: "ntfs:C:", Meta: &protocol.EvidenceMeta{Method: "ntfs"}}, now); e != nil {
		t.Fatal(e)
	}
	if e = f.store.PutEvidenceChunk(t.Context(), device, fp, queued.ID, 0, hex.EncodeToString(sum[:]), bytes.NewReader(pkg.Bytes()), now); e != nil {
		t.Fatal(e)
	}
	if e = f.store.FinishEvidence(t.Context(), device, fp, queued.ID, protocol.EvidenceFinish{Outcome: "ok", Size: int64(pkg.Len()), SHA256: hex.EncodeToString(sum[:])}, now); e != nil {
		t.Fatal(e)
	}
	if _, e = f.store.VerifyEvidence(t.Context(), time.Now); e != nil {
		t.Fatal(e)
	}
	base := "/api/v1/cases/" + c.ID + "/collections/" + queued.ID + "/ntfs"
	resp, body = f.do(t, "GET", base, nil, false)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"mft_rows":3`) {
		t.Fatalf("manifest %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", base+"/C/mft?q=evil&limit=10", nil, false)
	var page ntfs.Page
	if resp.StatusCode != 200 || json.Unmarshal(body, &page) != nil || len(page.Rows) != 1 || page.Rows[0][6] != "evil.exe" {
		t.Fatalf("page %d %s", resp.StatusCode, body)
	}
	if resp, _ = f.do(t, "GET", base+"/C/usn", nil, false); resp.StatusCode != 404 {
		t.Fatal("missing timeline", resp.StatusCode)
	}
	if resp, _ = f.do(t, "GET", base+"/C/mft?from=yesterday", nil, false); resp.StatusCode != 400 {
		t.Fatal("bad time accepted", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", base+"/C/mft?format=csv", nil, false)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "EntryNumber,") || !strings.Contains(resp.Header.Get("Content-Disposition"), "C-mft.csv") {
		t.Fatalf("csv %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID, nil, false)
	if strings.Count(string(body), `"action":"evidence_downloaded"`) != 2 {
		t.Fatalf("manifest and CSV not both recorded: %s", body)
	}
}
