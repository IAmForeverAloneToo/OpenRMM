package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// collect runs one dispatched job through start, one chunk, finish and
// verification.
func collect(t *testing.T, s *Store, device string, now time.Time, data []byte, meta *protocol.EvidenceMeta) protocol.EvidenceJob {
	t.Helper()
	ctx := context.Background()
	d, e := s.DispatchEvidence(ctx, device, "fp", now)
	if e != nil || d.Job == nil {
		t.Fatal("dispatch", d, e)
	}
	start := protocol.EvidenceStart{Size: int64(len(data)), Modified: now.UnixNano(), Resolved: `C:\resolved`, Meta: meta}
	if _, e = s.StartEvidence(ctx, device, "fp", d.Job.ID, start, now); e != nil {
		t.Fatal("start", e)
	}
	if len(data) > 0 {
		if e = s.PutEvidenceChunk(ctx, device, "fp", d.Job.ID, 0, digest(data), bytes.NewReader(data), now); e != nil {
			t.Fatal("chunk", e)
		}
	}
	if e = s.FinishEvidence(ctx, device, "fp", d.Job.ID, protocol.EvidenceFinish{Outcome: "ok", Size: int64(len(data)), SHA256: digest(data)}, now); e != nil {
		t.Fatal("finish", e)
	}
	if handled, e := s.VerifyEvidence(ctx, func() time.Time { return now }); !handled || e != nil {
		t.Fatal("verify", handled, e)
	}
	return *d.Job
}

// Registry hives and alternate data streams can be requested; the
// agent's metadata is checked, kept and recorded in the custody log; small
// streams of a collected file are collected on their own.
func TestEvidenceSourcesMetadataAndStreams(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	for _, c := range []struct {
		source, path string
		ok           bool
	}{
		{"file", `C:\Users\a\.ssh\id_ed25519`, true}, {"file", `C:\x\file.txt:Zone.Identifier`, true}, {"file", `C:\x\file.txt:s:$DATA`, true},
		{"file", `C:\x\file.txt:a:b`, false}, {"file", `C:\x\file.txt:`, false}, {"hive", "SYSTEM", true}, {"hive", "NTUSER:alice", true},
		{"hive", "USRCLASS:S-1-5-21-1-2-3-1001", true}, {"hive", "HARDWARE", false}, {"hive", `NTUSER:..`, false}, {"hive", `C:\Windows\System32\config\SAM`, false}, {"registry", "SYSTEM", false},
	} {
		if ValidEvidenceSource(c.source, c.path) != c.ok {
			t.Fatal("source", c)
		}
	}
	// A hive is dispatched as a hive.
	hive, e := s.QueueEvidenceSource(ctx, caseID, device, "hive", "SYSTEM", "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	job := collect(t, s, device, now, []byte("regf hive"), &protocol.EvidenceMeta{Method: "registry_save"})
	if job.ID != hive || job.Source != "hive" || job.Path != "SYSTEM" {
		t.Fatalf("hive job %+v", job)
	}
	// Invalid metadata is refused at start.
	if _, e = s.QueueEvidence(ctx, caseID, device, `C:\bad.txt`, "owner", now); e != nil {
		t.Fatal(e)
	}
	d, _ := s.DispatchEvidence(ctx, device, "fp", now)
	if _, e = s.StartEvidence(ctx, device, "fp", d.Job.ID, protocol.EvidenceStart{Size: 1, Meta: &protocol.EvidenceMeta{Method: "magic"}}, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("invalid method accepted", e)
	}
	if e = s.CancelEvidence(ctx, caseID, d.Job.ID, "owner", now); e != nil {
		t.Fatal(e)
	}

	// A file with three streams: two small readable ones are collected on
	// their own; a large one and an unreadable one are only listed.
	if _, e = s.QueueEvidence(ctx, caseID, device, `C:\Users\a\Downloads\invoice.pdf`, "owner", now); e != nil {
		t.Fatal(e)
	}
	meta := &protocol.EvidenceMeta{Method: "backup", Accessed: now.UnixNano(), Changed: now.UnixNano(), Attributes: 0x20, Owner: `PC\alice`, OwnerSID: "S-1-5-21-1-2-3-1001", Streams: []protocol.EvidenceStream{
		{Name: "Zone.Identifier", Size: 26, SHA256: digest([]byte("zone"))}, {Name: "small", Size: 10, SHA256: digest([]byte("s"))},
		{Name: "big", Size: protocol.SmallStream + 1}, {Name: "locked", Size: 5},
	}}
	parent := collect(t, s, device, now, []byte("%PDF"), meta)
	jobs, _ := s.EvidenceJobs(ctx, caseID)
	children := map[string]EvidenceJob{}
	for _, j := range jobs {
		if j.ParentID == parent.ID {
			children[j.Path] = j
		}
		if j.ID == parent.ID {
			var m protocol.EvidenceMeta
			if json.Unmarshal(j.Meta, &m) != nil || m.Owner != `PC\alice` || len(m.Streams) != 4 {
				t.Fatalf("stored meta %s", j.Meta)
			}
		}
	}
	if len(children) != 2 || children[`C:\Users\a\Downloads\invoice.pdf:Zone.Identifier`].Status != "queued" || children[`C:\Users\a\Downloads\invoice.pdf:small`].Actor != "owner" {
		t.Fatalf("stream collections %+v", children)
	}
	detail, _ := s.CaseDetail(ctx, caseID)
	var collected CustodyEntry
	for _, x := range detail.Entries {
		if x.Action == "evidence_collected" && x.Details["job"] == parent.ID {
			collected = x
		}
	}
	if collected.Details["method"] != "backup" || collected.Details["owner"] != `PC\alice` || collected.Details["attributes"] != "0x20" || !strings.Contains(collected.Details["streams"], "locked 5 unreadable") || !strings.Contains(collected.Details["streams"], "big 1048577 not_hashed") || collected.Details["file_accessed"] == "" || collected.Details["file_changed"] == "" {
		t.Fatalf("custody details %+v", collected.Details)
	}
	// A stream's own collection queues no further ones and names its parent.
	child := collect(t, s, device, now, []byte("zone"), &protocol.EvidenceMeta{Method: "read", Streams: []protocol.EvidenceStream{{Name: "x", Size: 1, SHA256: digest([]byte("x"))}}})
	jobs, _ = s.EvidenceJobs(ctx, caseID)
	var stored EvidenceJob
	for _, j := range jobs {
		if j.ParentID == child.ID {
			t.Fatal("a stream queued streams")
		}
		if j.ID == child.ID {
			stored = j
		}
	}
	if stored.Name() != "invoice.pdf_Zone.Identifier" && stored.Name() != "invoice.pdf_small" {
		t.Fatal("stream file name", stored.Name())
	}
	// Streams of a file read from a shadow copy are listed, not queued.
	if _, e = s.QueueEvidence(ctx, caseID, device, `C:\locked.db`, "owner", now); e != nil {
		t.Fatal(e)
	}
	shadowed := collect(t, s, device, now, []byte("db"), &protocol.EvidenceMeta{Method: "shadow_copy", Snapshot: "{AB9DA96A-726D-4595-9498-79F2AC841B0A}", SnapshotAt: now.UnixNano(), Streams: []protocol.EvidenceStream{{Name: "x", Size: 1, SHA256: digest([]byte("x"))}}})
	jobs, _ = s.EvidenceJobs(ctx, caseID)
	for _, j := range jobs {
		if j.ParentID == shadowed.ID {
			t.Fatal("a shadow-copy file queued streams")
		}
	}
	// A resumed upload with another shadow copy is a different content.
	if _, e = s.QueueEvidence(ctx, caseID, device, `C:\locked2.db`, "owner", now); e != nil {
		t.Fatal(e)
	}
	d, _ = s.DispatchEvidence(ctx, device, "fp", now)
	first := protocol.EvidenceStart{Size: 1, Modified: 1, Meta: &protocol.EvidenceMeta{Method: "shadow_copy", Snapshot: "{AB9DA96A-726D-4595-9498-79F2AC841B0A}", SnapshotAt: 1}}
	if _, e = s.StartEvidence(ctx, device, "fp", d.Job.ID, first, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StartEvidence(ctx, device, "fp", d.Job.ID, first, now); e != nil {
		t.Fatal("same copy refused", e)
	}
	second := first
	second.Meta = &protocol.EvidenceMeta{Method: "shadow_copy", Snapshot: "{BB9DA96A-726D-4595-9498-79F2AC841B0A}", SnapshotAt: 2}
	if _, e = s.StartEvidence(ctx, device, "fp", d.Job.ID, second, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("resumed from another shadow copy", e)
	}
	if (EvidenceJob{Source: "hive", Path: "NTUSER:alice"}).Name() != "hive-NTUSER-alice.dat" {
		t.Fatal("hive file name")
	}
	detail, _ = s.CaseDetail(ctx, caseID)
	if !detail.Verified {
		t.Fatal(detail.Problem)
	}
}
