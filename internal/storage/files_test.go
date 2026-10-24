package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"strings"
	"testing"
	"time"
)

func rollbackFileSchema(t *testing.T, s *Store) {
	t.Helper()
	rollbackAgentUpdateSchema(t, s)
	var n int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=22").Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n == 0 {
		return
	}
	for _, q := range []string{"DROP TABLE file_jobs", "DROP TABLE device_file_support", "DELETE FROM schema_migrations WHERE version=22"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}
func fileFixture(t *testing.T) (*Store, Device, time.Time) {
	s, d, now := actionFixture(t)
	raw, _ := json.Marshal(protocol.FileSupport{Roots: []protocol.FileRoot{{ID: "support", Name: "Support", Read: true, Write: true}}})
	if e := s.RecordFileSupport(context.Background(), d.ID, d.Fingerprint, protocol.FeatureReport{Capability: filetransfer.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, now
}
func fileTestJob(op string) protocol.FileJob {
	q := protocol.FileJob{ID: strings.Repeat("a", 32), Operation: op, Root: "support", Path: "file.bin", ExpiresAt: 1}
	if op == "list" {
		q.Path = "."
	}
	if op == "upload" {
		q.Data = []byte("fixture")
		q.Size = int64(len(q.Data))
		q.Hash = filetransfer.Digest(q.Data)
	}
	return q
}
func TestFilesReviewedUploadNoRedeliveryAndExpiry(t *testing.T) {
	s, d, now := fileFixture(t)
	ctx := context.Background()
	v := Session{Username: "admin"}
	q := fileTestJob("upload")
	if e := s.QueueFile(ctx, q, d.ID, v.Actor(), now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	dispatch, e := s.DispatchFile(ctx, d.ID, d.Fingerprint, now)
	if e != nil || dispatch.Job != nil {
		t.Fatal("unconfirmed upload dispatched", e)
	}
	if e = s.ConfirmFile(ctx, v, d.ID, q.ID, now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if e = s.ConfirmFile(ctx, v, d.ID, q.ID, now, 120*time.Second); e != nil {
		t.Fatal("confirm replay", e)
	}
	if _, e = s.DispatchFile(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("wrong cert", e)
	}
	dispatch, e = s.DispatchFile(ctx, d.ID, d.Fingerprint, now)
	if e != nil || dispatch.Job == nil || string(dispatch.Job.Data) != string(q.Data) {
		t.Fatal("payload", e)
	}
	dispatch, e = s.DispatchFile(ctx, d.ID, d.Fingerprint, now)
	if e != nil || dispatch.Job != nil {
		t.Fatal("redelivery", e)
	}
	if e = s.CancelFile(ctx, v, d.ID, q.ID, now); e != nil {
		t.Fatal(e)
	}
	jobs, e := s.FileJobs(ctx, v, d.ID, now)
	if e != nil || len(jobs) != 1 || jobs[0].Status != "unknown" {
		t.Fatal("false rollback", e, jobs)
	}
	q.ID = strings.Repeat("b", 32)
	if e = s.QueueFile(ctx, q, d.ID, v.Actor(), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e = s.SweepFiles(ctx, now.Add(16*time.Minute)); e != nil {
		t.Fatal(e)
	}
	var size, reserve int
	if e = s.db.QueryRow("SELECT length(payload),reserve_bytes FROM file_jobs WHERE id=?", q.ID).Scan(&size, &reserve); e != nil || size != 0 || reserve != 0 {
		t.Fatal("expired content retained", e)
	}
}
func TestFileDownloadsIntegrityScopeAndRevocation(t *testing.T) {
	s, d, now := fileFixture(t)
	ctx := context.Background()
	v := Session{Username: "admin"}
	q := fileTestJob("download")
	if e := s.QueueFile(ctx, q, d.ID, v.Actor(), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	out, e := s.DispatchFile(ctx, d.ID, d.Fingerprint, now)
	if e != nil || out.Job == nil {
		t.Fatal(e)
	}
	r := protocol.FileResult{ID: q.ID, Outcome: "succeeded", Data: []byte("download"), Size: 8, Hash: filetransfer.Digest([]byte("download"))}
	bad := r
	bad.Hash = strings.Repeat("0", 64)
	if e = s.CompleteFile(ctx, d.ID, d.Fingerprint, bad, now); !errors.Is(e, ErrFile) {
		t.Fatal("bad digest", e)
	}
	if e = s.CompleteFile(ctx, d.ID, d.Fingerprint, r, now); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteFile(ctx, d.ID, d.Fingerprint, r, now); e != nil {
		t.Fatal("result replay", e)
	}
	_, data, e := s.FileDownload(ctx, v, d.ID, q.ID, now)
	if e != nil || string(data) != "download" {
		t.Fatal("download", e)
	}
	tech := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	if _, _, e = s.FileDownload(ctx, tech, d.ID, q.ID, now); !errors.Is(e, ErrForbidden) {
		t.Fatal("read-only technician received content", e)
	}
	if _, e = s.FileJobs(ctx, tech, d.ID, now); !errors.Is(e, ErrForbidden) {
		t.Fatal("file metadata permission bypass", e)
	}
	tech.Technician.Access.Files = true
	access, _ := json.Marshal(tech.Technician.Access)
	if _, e = s.db.Exec("UPDATE technicians SET access_json=?", string(access)); e != nil {
		t.Fatal(e)
	}
	if _, data, e = s.FileDownload(ctx, tech, d.ID, q.ID, now); e != nil || string(data) != "download" {
		t.Fatal("explicit scoped file grant denied", e)
	}
	if _, e = s.db.Exec("UPDATE technicians SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.FileDownload(ctx, tech, d.ID, q.ID, now); !errors.Is(e, ErrForbidden) {
		t.Fatal("disabled technician downloaded", e)
	}
	if _, _, e = s.FileDownload(ctx, v, d.ID, q.ID, now.Add(16*time.Minute)); !errors.Is(e, ErrFile) {
		t.Fatal("expired download", e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DispatchFile(ctx, d.ID, d.Fingerprint, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("revoked polling", e)
	}
}
func TestFileAuditFailureRollsBackAndLiveActorRevocation(t *testing.T) {
	s, d, now := fileFixture(t)
	ctx := context.Background()
	tech := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}, Files: true})
	q := fileTestJob("list")
	if e := s.QueueFile(ctx, q, d.ID, tech.Actor(), now, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("UPDATE technicians SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	out, e := s.DispatchFile(ctx, d.ID, d.Fingerprint, now)
	if e != nil || out.Job != nil {
		t.Fatal("disabled actor dispatch", e)
	}
	jobs, e := s.FileJobs(ctx, Session{Username: "admin"}, d.ID, now)
	if e != nil || len(jobs) != 1 || jobs[0].Status != "expired" {
		t.Fatal("live revoke", e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER file_test_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	q.ID = strings.Repeat("b", 32)
	if e = s.QueueFile(ctx, q, d.ID, "admin", now, time.Minute); e == nil {
		t.Fatal("missing audit accepted")
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM file_jobs WHERE id=?", q.ID).Scan(&n)
	if n != 0 {
		t.Fatal("partial queue")
	}
}
func TestFileMetadataLookupCurrentActorExactDeviceAndNoPayload(t *testing.T) {
	s, d, now := fileFixture(t)
	ctx := context.Background()
	q := fileTestJob("upload")
	if e := s.QueueFile(ctx, q, d.ID, "admin", now, time.Minute); e != nil {
		t.Fatal(e)
	}
	a, e := s.FileJob(ctx, Session{Username: "admin"}, d.ID, q.ID, now)
	if e != nil || len(a.Data) != 0 || a.Hash != q.Hash || a.Status != "staged" {
		t.Fatal("metadata/payload boundary", e)
	}
	if e = s.CancelFile(ctx, Session{Username: "admin"}, d.ID, q.ID, now); e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 51; i++ {
		newJob := q
		newJob.ID = fmt.Sprintf("%032x", i)
		at := now.Add(time.Duration(i) * time.Second)
		if e = s.QueueFile(ctx, newJob, d.ID, "admin", at, time.Minute); e != nil {
			t.Fatal(e)
		}
		if e = s.CancelFile(ctx, Session{Username: "admin"}, d.ID, newJob.ID, at); e != nil {
			t.Fatal(e)
		}
	}
	if jobs, e := s.FileJobs(ctx, Session{Username: "admin"}, d.ID, now.Add(52*time.Second)); e != nil || len(jobs) != 50 {
		t.Fatal("history bound", len(jobs), e)
	} else {
		for _, job := range jobs {
			if job.ID == q.ID {
				t.Fatal("fixture did not move outside latest 50")
			}
		}
	}
	if a, e = s.FileJob(ctx, Session{Username: "admin"}, d.ID, q.ID, now); e != nil || a.ID != q.ID {
		t.Fatal("older retained detail", e)
	}
	if _, e = s.FileJob(ctx, Session{Username: "admin"}, strings.Repeat("f", 32), q.ID, now); e == nil {
		t.Fatal("foreign device lookup")
	}
	tech := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}, Files: true})
	if _, e = s.FileJob(ctx, tech, d.ID, q.ID, now); e != nil {
		t.Fatal("explicit grant", e)
	}
	if _, e = s.db.Exec("UPDATE technicians SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FileJob(ctx, tech, d.ID, q.ID, now); !errors.Is(e, ErrForbidden) {
		t.Fatal("stale actor projection accepted", e)
	}
	if e = s.RevokeDevice(ctx, d.ID, now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FileJob(ctx, Session{Username: "admin"}, d.ID, q.ID, now); e == nil {
		t.Fatal("revoked device metadata")
	}
}
