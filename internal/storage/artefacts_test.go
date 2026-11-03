package storage

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// triagePackage is a package with one version 17 prefetch file.
func triagePackage(t *testing.T) []byte {
	pf := make([]byte, 0x200)
	binary.LittleEndian.PutUint32(pf, 17)
	copy(pf[4:], "SCCA")
	copy(pf[16:], []byte{'C', 0, 'M', 0, 'D', 0})
	binary.LittleEndian.PutUint32(pf[144:], 5)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("C/Windows/Prefetch/CMD-0BD30981.pf")
	w.Write(pf)
	w, _ = zw.Create("manifest.json")
	w.Write([]byte("{}"))
	if e := zw.Close(); e != nil {
		t.Fatal(e)
	}
	return buf.Bytes()
}

// collectTriage runs a triage collection to a verified package.
func collectTriage(t *testing.T, s *Store, caseID, device string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	if e := s.RecordHeartbeat(ctx, device, "fp", protocol.Heartbeat{Hostname: "pc", OS: "windows", Architecture: "amd64", AgentVersion: "test", Abilities: []string{protocol.AbilityTriage}}, now); e != nil {
		t.Fatal(e)
	}
	full, e := s.TriageProfileByID(ctx, FullTriage)
	if e != nil {
		t.Fatal(e)
	}
	job, e := s.QueueTriage(ctx, caseID, device, "", full, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DispatchEvidence(ctx, device, "fp", now); e != nil {
		t.Fatal(e)
	}
	data := triagePackage(t)
	if _, e = s.StartEvidence(ctx, device, "fp", job, protocol.EvidenceStart{Size: int64(len(data)), Resolved: "Full triage", Meta: &protocol.EvidenceMeta{Method: "triage"}}, now); e != nil {
		t.Fatal(e)
	}
	if e = s.PutEvidenceChunk(ctx, device, "fp", job, 0, digest(data), bytes.NewReader(data), now); e != nil {
		t.Fatal(e)
	}
	if e = s.FinishEvidence(ctx, device, "fp", job, protocol.EvidenceFinish{Outcome: "ok", Size: int64(len(data)), SHA256: digest(data)}, now); e != nil {
		t.Fatal(e)
	}
	if handled, e := s.VerifyEvidence(ctx, func() time.Time { return now }); !handled || e != nil {
		t.Fatal("verify", handled, e)
	}
	return job
}

// A verified triage package is queued for parsing; the results are stored
// like evidence, listed with the collection, opened with a custody entry and
// counted toward the quota.
func TestArtefactParseLifecycle(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	job := collectTriage(t, s, caseID, device, now)
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	if jobs[0].Parse == nil || jobs[0].Parse.Status != "queued" {
		t.Fatalf("not queued: %+v", jobs[0].Parse)
	}
	if e := s.QueueParse(ctx, caseID, job, "owner", now); !errors.Is(e, ErrParseBusy) {
		t.Fatal("queued twice", e)
	}
	task, ok, e := s.ClaimParse(ctx, now)
	if e != nil || !ok || task.JobID != job || task.Request.Source != "triage" || task.Request.Name != "Full triage" || !task.QuotaBound {
		t.Fatalf("claim %+v %v %v", task, ok, e)
	}
	if _, ok, _ := s.ClaimParse(ctx, now); ok {
		t.Fatal("claimed twice")
	}
	m, e := artefacts.Parse(ctx, task.Request)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.FinishParse(ctx, task, m, now); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(task.Request.Temp); !os.IsNotExist(e) {
		t.Fatal("temporary folder left behind")
	}
	jobs, _ = s.EvidenceJobs(ctx, caseID)
	p := jobs[0].Parse
	var tables []ParseTable
	if p == nil || p.Status != "succeeded" || p.Parser != artefacts.ParserVersion || p.Size == 0 || json.Unmarshal(p.Tables, &tables) != nil || len(tables) != 1 || tables[0] != (ParseTable{Name: "prefetch", Title: "Prefetch", Rows: 1}) {
		t.Fatalf("listed %+v", p)
	}
	f, _, e := s.OpenParsed(ctx, caseID, job, "owner", true, now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	zr, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	tf, e := zr.Open("tables/prefetch.csv")
	if e != nil {
		t.Fatal(e)
	}
	csv, _ := io.ReadAll(tf)
	if !strings.Contains(string(csv), `C:\Windows\Prefetch\CMD-0BD30981.pf,CMD,`) {
		t.Fatal(string(csv))
	}
	// The results count toward the quota.
	tx, _ := s.db.BeginTx(ctx, nil)
	used, _ := s.quotaUsed(ctx, tx)
	tx.Rollback()
	if used != jobs[0].Size+p.Size {
		t.Fatal("quota", used, jobs[0].Size, p.Size)
	}
	// Parsed again on request; an output limit at the quota reads as quota.
	if e = s.QueueParse(ctx, caseID, job, "owner", now); e != nil {
		t.Fatal(e)
	}
	task, _, _ = s.ClaimParse(ctx, now)
	if e = s.FailParse(ctx, task, artefacts.OutcomeOutputLimit, now); e != nil {
		t.Fatal(e)
	}
	jobs, _ = s.EvidenceJobs(ctx, caseID)
	if jobs[0].Parse.Status != "failed" || jobs[0].Parse.Outcome != "quota" {
		t.Fatalf("%+v", jobs[0].Parse)
	}
	if _, _, e = s.OpenParsed(ctx, caseID, job, "owner", false, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("failed parse opened", e)
	}
	// A parse the server ended with is restarted, and given up after three.
	if e = s.QueueParse(ctx, caseID, job, "owner", now); e != nil {
		t.Fatal(e)
	}
	for range 3 {
		if _, ok, _ = s.ClaimParse(ctx, now); !ok {
			t.Fatal("not restarted")
		}
		if e = s.RecoverParses(ctx, now); e != nil {
			t.Fatal(e)
		}
	}
	jobs, _ = s.EvidenceJobs(ctx, caseID)
	if jobs[0].Parse.Status != "failed" || jobs[0].Parse.Outcome != "crashed" {
		t.Fatalf("%+v", jobs[0].Parse)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	var actions []string
	for _, x := range detail.Entries {
		actions = append(actions, x.Action)
	}
	if !detail.Verified || !strings.HasSuffix(strings.Join(actions, ","), "evidence_collected,artefacts_parsed,evidence_downloaded,artefacts_parse_requested,artefacts_parsed,artefacts_parse_requested,artefacts_parsed") {
		t.Fatal(actions)
	}
	// Other collections are not parsed.
	if e = s.QueueParse(ctx, caseID, "nope", "owner", now); !errors.Is(e, ErrEvidence) {
		t.Fatal(e)
	}
}
