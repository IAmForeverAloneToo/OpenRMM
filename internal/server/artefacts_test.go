package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// A triage package is parsed by the server's parsing process once it is
// verified, and read back from the case page: manifest, filtered pages,
// CSV and the whole results; it can be parsed again on request.
func TestArtefactsAPI(t *testing.T) {
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
	cred, e := f.devices.Enroll(t.Context(), protocol.Enrollment{Token: token, CSR: csr, Hostname: "WS-PARSE", OS: "windows", Architecture: "amd64"}, "test")
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode([]byte(cred.Certificate))
	fp, device, now := deviceidentity.Fingerprint(block.Bytes), cred.DeviceID, time.Now()
	if e = f.store.RecordHeartbeat(t.Context(), device, fp, protocol.Heartbeat{Hostname: "WS-PARSE", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityTriage}}, now); e != nil {
		t.Fatal(e)
	}
	resp, body := f.do(t, "POST", "/api/v1/cases", map[string]string{"title": "Parse"}, true)
	var c storage.Case
	if resp.StatusCode != 201 || json.Unmarshal(body, &c) != nil {
		t.Fatal("case", resp.StatusCode)
	}
	resp, body = f.do(t, "POST", "/api/v1/cases/"+c.ID+"/collect", map[string]any{"device_id": device, "source": "triage", "profile": storage.FullTriage}, true)
	var queued struct {
		ID string `json:"id"`
	}
	if resp.StatusCode != 201 || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("collect %d %s", resp.StatusCode, body)
	}
	// The device uploads a package with two prefetch files.
	var pkg bytes.Buffer
	zw := zip.NewWriter(&pkg)
	for _, exe := range []string{"CMD.EXE", "EVIL.EXE"} {
		pf := make([]byte, 0x200)
		binary.LittleEndian.PutUint32(pf, 17)
		copy(pf[4:], "SCCA")
		for i, r := range exe {
			pf[16+2*i] = byte(r)
		}
		binary.LittleEndian.PutUint32(pf[144:], 2)
		w, _ := zw.Create("C/Windows/Prefetch/" + exe + "-00000001.pf")
		w.Write(pf)
	}
	zw.Close()
	if _, e = f.store.DispatchEvidence(t.Context(), device, fp, now); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(pkg.Bytes())
	if _, e = f.store.StartEvidence(t.Context(), device, fp, queued.ID, protocol.EvidenceStart{Size: int64(pkg.Len()), Resolved: "Full triage", Meta: &protocol.EvidenceMeta{Method: "triage"}}, now); e != nil {
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
	base := "/api/v1/cases/" + c.ID + "/collections/" + queued.ID
	if resp, _ = f.do(t, "GET", base+"/parsed", nil, false); resp.StatusCode != 404 {
		t.Fatal("results before parsing", resp.StatusCode)
	}
	// The parsing worker runs it in a separate process.
	parse := func() {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { defer close(done); runArtefactParser(ctx, f.store, slog.New(slog.DiscardHandler)) }()
		defer func() { cancel(); <-done }()
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			jobs, _ := f.store.EvidenceJobs(t.Context(), c.ID)
			if p := jobs[0].Parse; p != nil && p.Status != "queued" && p.Status != "running" {
				return
			}
		}
		t.Fatal("not parsed in time")
	}
	parse()
	resp, body = f.do(t, "GET", base+"/parsed", nil, false)
	var m artefacts.Manifest
	if resp.StatusCode != 200 || json.Unmarshal(body, &m) != nil || len(m.Tables) != 1 || m.Tables[0].Rows != 2 {
		t.Fatalf("manifest %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", base+"/parsed/prefetch?q=evil&limit=10", nil, false)
	var page artefacts.Page
	if resp.StatusCode != 200 || json.Unmarshal(body, &page) != nil || len(page.Rows) != 1 || page.Rows[0][1] != "EVIL.EXE" {
		t.Fatalf("page %d %s", resp.StatusCode, body)
	}
	for _, bad := range []string{"/parsed/prefetch?from=yesterday", "/parsed/prefetch?limit=501", "/parsed/Nope"} {
		if resp, _ = f.do(t, "GET", base+bad, nil, false); resp.StatusCode != 400 && resp.StatusCode != 404 {
			t.Fatal(bad, resp.StatusCode)
		}
	}
	if resp, _ = f.do(t, "GET", base+"/parsed/registry", nil, false); resp.StatusCode != 404 {
		t.Fatal("missing table", resp.StatusCode)
	}
	resp, body = f.do(t, "GET", base+"/parsed/prefetch?format=csv", nil, false)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "SourceFile,") || !strings.Contains(resp.Header.Get("Content-Disposition"), "-prefetch.csv") {
		t.Fatalf("csv %d %s", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", base+"/parsed?format=zip", nil, false)
	if zr, e := zip.NewReader(bytes.NewReader(body), int64(len(body))); resp.StatusCode != 200 || e != nil || len(zr.File) != 2 {
		t.Fatalf("zip %d %v", resp.StatusCode, e)
	}
	// Parsed again on request.
	if resp, _ = f.do(t, "POST", base+"/parse", nil, true); resp.StatusCode != 202 {
		t.Fatal("parse again", resp.StatusCode)
	}
	if resp, _ = f.do(t, "POST", base+"/parse", nil, true); resp.StatusCode != 409 {
		t.Fatal("parsed twice at once", resp.StatusCode)
	}
	parse()
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID, nil, false)
	if strings.Count(string(body), `"action":"evidence_downloaded"`) != 3 || strings.Count(string(body), `"action":"artefacts_parsed"`) != 2 {
		t.Fatalf("custody: %s", body)
	}
	resp, body = f.do(t, "GET", "/api/v1/cases/"+c.ID+"/collections", nil, false)
	if !strings.Contains(string(body), `"parse":{"status":"succeeded"`) {
		t.Fatalf("listing %s", body)
	}
}
