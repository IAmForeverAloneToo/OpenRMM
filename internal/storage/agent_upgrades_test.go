package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rollbackAgentUpdateSchema(t *testing.T, s *Store) {
	t.Helper()
	rollbackFeatureSettings(t, s.db)
	for _, q := range []string{"DROP TABLE IF EXISTS agent_ring_policy", "DELETE FROM schema_migrations WHERE version=27", "DROP TABLE IF EXISTS script_batches", "DELETE FROM schema_migrations WHERE version=26", "DROP TABLE IF EXISTS metric_buckets", "DROP TABLE IF EXISTS metric_receipts", "DELETE FROM schema_migrations WHERE version=25", "DROP TABLE IF EXISTS patch_runs", "DROP TABLE IF EXISTS patch_device_guards", "DROP TABLE IF EXISTS patch_policies", "DELETE FROM schema_migrations WHERE version=24", "DROP TABLE IF EXISTS agent_upgrade_jobs", "DROP TABLE IF EXISTS device_agent_upgrade_support", "DROP TABLE IF EXISTS agent_releases", "DROP TABLE IF EXISTS agent_release_state", "DELETE FROM schema_migrations WHERE version=23"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}
func upgradeFixture(t *testing.T) (*Store, Device, AgentRelease, time.Time) {
	t.Helper()
	s, d, _, now := applicationFixture(t)
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.2", Sequence: 5, Size: 8, Hash: agentupdate.Digest([]byte("artifact")), KeyID: agentupdate.Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	release := protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, agentupdate.Message(m)))}
	r := AgentRelease{ID: agentupdate.ReleaseID(release), Release: release, PublicKey: hex.EncodeToString(public)}
	raw, _ := json.Marshal(release)
	if _, e = s.db.Exec("INSERT INTO agent_releases(id,signed_json,public_key,key_id,sequence,created_at,actor)VALUES(?,?,?,?,?,?,?)", r.ID, string(raw), r.PublicKey, m.KeyID, m.Sequence, now.Unix(), "admin"); e != nil {
		t.Fatal(e)
	}
	root, e := s.agentArtifactRoot()
	if e != nil {
		t.Fatal(e)
	}
	root.Close()
	if e = os.WriteFile(filepath.Join(root.Name(), r.ID+".exe"), []byte("artifact"), 0600); e != nil {
		t.Fatal(e)
	}
	support := protocol.AgentUpgradeSupport{Broker: "enabled", CurrentHash: strings.Repeat("c", 64), KeyIDs: []string{m.KeyID}}
	report, _ := json.Marshal(support)
	if e = s.RecordAgentUpgradeSupport(context.Background(), d.ID, d.Fingerprint, protocol.FeatureReport{Capability: agentupdate.Capability, Status: "ok", Data: report}, now); e != nil {
		t.Fatal(e)
	}
	return s, d, r, now
}
func upgradeQueue(t *testing.T, s *Store, d Device, r AgentRelease, now time.Time) AgentRolloutReview {
	t.Helper()
	c := AgentRolloutChange{ID: strings.Repeat("a", 32), ReleaseID: r.ID, Devices: []string{d.ID}, Groups: []string{}}
	review, e := s.QueueAgentRollout(context.Background(), c, "admin", "", now, 120*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.QueueAgentRollout(context.Background(), c, "admin", review.Digest, now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	return review
}
func TestAgentUpgradeReviewedDispatchIsOneShot(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	ctx := context.Background()
	review := upgradeQueue(t, s, d, r, now)
	if len(review.Targets) != 1 {
		t.Fatal(review)
	}
	out, e := s.DispatchAgentUpgrade(ctx, d.ID, d.Fingerprint, now)
	if e != nil || out.Job == nil {
		t.Fatal(out, e)
	}
	again, e := s.DispatchAgentUpgrade(ctx, d.ID, d.Fingerprint, now)
	if e != nil || again.Job != nil {
		t.Fatal("redelivery", again, e)
	}
	_, f, e := s.AgentReleaseArtifact(ctx, d.ID, d.Fingerprint, out.Job.ID, now)
	if e != nil {
		t.Fatal(e)
	}
	f.Close()
	if e = s.WithdrawAgentRelease(ctx, r.ID, "admin", now); e == nil {
		t.Fatal("withdrew dispatched artifact")
	}
	bad := protocol.AgentUpgradeResult{ID: out.Job.ID, Outcome: "succeeded", Hash: strings.Repeat("d", 64), Sequence: 5}
	if e = s.CompleteAgentUpgrade(ctx, d.ID, d.Fingerprint, bad, now); e == nil {
		t.Fatal("wrong digest success")
	}
	bad.Hash = r.Release.Manifest.Hash
	if e = s.CompleteAgentUpgrade(ctx, d.ID, d.Fingerprint, bad, now); e != nil {
		t.Fatal(e)
	}
	if e = s.CompleteAgentUpgrade(ctx, d.ID, d.Fingerprint, bad, now); e != nil {
		t.Fatal("duplicate outcome", e)
	}
	if _, f, e = s.AgentReleaseArtifact(ctx, d.ID, d.Fingerprint, out.Job.ID, now); e == nil {
		f.Close()
		t.Fatal("terminal job still downloads")
	}
}
func TestAgentUpgradeReviewRejectsChangedSourceAndStaleSupport(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	ctx := context.Background()
	review := upgradeQueue(t, s, d, r, now)
	if _, e := s.QueueAgentRollout(ctx, review.Change, "technician:x", review.Digest, now, 120*time.Second); e == nil {
		t.Fatal("technician rollout")
	}
	if _, e := s.db.Exec("UPDATE device_agent_upgrade_support SET reported_at=?", now.Add(-3*time.Minute).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QueueAgentRollout(ctx, review.Change, "admin", review.Digest, now, 120*time.Second); e == nil {
		t.Fatal("stale review")
	}
	if _, e := s.DispatchAgentUpgrade(ctx, d.ID, d.Fingerprint, now); e == nil {
		t.Fatal("stale dispatch")
	}
}
func TestAgentUpgradeLostResultExpiresUnknownWithoutReplay(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	ctx := context.Background()
	upgradeQueue(t, s, d, r, now)
	out, e := s.DispatchAgentUpgrade(ctx, d.ID, d.Fingerprint, now)
	if e != nil || out.Job == nil {
		t.Fatal(e)
	}
	rows, e := s.AgentUpgradeJobs(ctx, Session{Username: "admin"}, d.ID, now.Add(11*time.Minute))
	if e != nil || len(rows) != 1 || rows[0].Status != "unknown" {
		t.Fatal(rows, e)
	}
	if e = s.CancelAgentUpgrade(ctx, out.Job.ID, "admin", now); e == nil {
		t.Fatal("cancelled dispatched work")
	}
	if e = s.CompleteAgentUpgrade(ctx, d.ID, d.Fingerprint, protocol.AgentUpgradeResult{ID: out.Job.ID, Outcome: "succeeded", Hash: r.Release.Manifest.Hash, Sequence: 5}, now.Add(11*time.Minute)); e == nil {
		t.Fatal("late result falsely final")
	}
}
func TestAgentUpgradeWithdrawalCancelsQueuedAndRemovesArtifact(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	ctx := context.Background()
	upgradeQueue(t, s, d, r, now)
	if e := s.WithdrawAgentRelease(ctx, r.ID, "admin", now); e != nil {
		t.Fatal(e)
	}
	rows, e := s.AgentUpgradeJobs(ctx, Session{Username: "admin"}, d.ID, now)
	if e != nil || rows[0].Status != "cancelled" {
		t.Fatal(rows, e)
	}
	if _, e = os.Stat(filepath.Join(s.directory, "agent-releases", r.ID+".exe")); !os.IsNotExist(e) {
		t.Fatal("artifact retained", e)
	}
}
func TestAgentUpgradeMigrationPreservesSchema22(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := s.Info(ctx)
	rollbackAgentUpdateSchema(t, s)
	s.Close()
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, _ := s.Info(ctx)
	if before != after {
		t.Fatal("identity changed")
	}
}

func TestAgentUpgradeScopedHistory(t *testing.T) {
	s, d, r, now := upgradeFixture(t)
	upgradeQueue(t, s, d, r, now)
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	v.Technician.Access.Devices = []string{strings.Repeat("f", 32)}
	raw, _ := json.Marshal(v.Technician.Access)
	if _, e := s.db.Exec("UPDATE technicians SET access_json=? WHERE id=?", string(raw), v.Technician.ID); e != nil {
		t.Fatal(e)
	}
	rows, e := s.AgentUpgradeJobs(context.Background(), v, "", now)
	if e != nil || len(rows) != 0 {
		t.Fatal("out of scope history leaked", rows, e)
	}
	v.Technician.Access.Devices = []string{d.ID}
	raw, _ = json.Marshal(v.Technician.Access)
	if _, e = s.db.Exec("UPDATE technicians SET access_json=? WHERE id=?", string(raw), v.Technician.ID); e != nil {
		t.Fatal(e)
	}
	rows, e = s.AgentUpgradeJobs(context.Background(), v, "", now)
	if e != nil || len(rows) != 1 {
		t.Fatal("authorized history missing", e)
	}
}
