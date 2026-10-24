package agentupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func signedJob(t *testing.T, seq int64) (protocol.AgentUpgradeJob, string) {
	t.Helper()
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	m := protocol.AgentManifest{Format: 1, Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.2", Sequence: seq, Size: 100, Hash: strings.Repeat("b", 64), KeyID: Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	r := protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, Message(m)))}
	key := hex.EncodeToString(public)
	return protocol.AgentUpgradeJob{ID: strings.Repeat("a", 32), Release: r, PublicKey: key, ExpectedHash: strings.Repeat("c", 64), ExpiresAt: now.Add(time.Minute).Unix()}, key
}

type fakePlatform struct {
	mu                        sync.Mutex
	hash, old, next           string
	replaces, restores, stops int
	failStart                 bool
}

func (p *fakePlatform) Current() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hash, nil
}
func (p *fakePlatform) Prepare(q protocol.AgentUpgradeJob) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.old = p.hash
	p.next = q.Release.Manifest.Hash
	return nil
}
func (p *fakePlatform) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stops++
	return nil
}
func (p *fakePlatform) Replace() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.replaces++
	p.hash = p.next
	return nil
}
func (p *fakePlatform) Start(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failStart && p.hash == p.next {
		return errors.New("failed startup")
	}
	return nil
}
func (p *fakePlatform) Restore(old, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.restores++
	p.hash = old
	return nil
}
func (p *fakePlatform) Peer(pid uint32, hash string) bool {
	v, _ := p.Current()
	return pid == 123 && v == hash
}
func (p *fakePlatform) Active(hash string) bool { v, _ := p.Current(); return v == hash }
func brokerFixture(t *testing.T, enabled bool) (*Broker, *fakePlatform, protocol.AgentUpgradeJob, context.CancelFunc) {
	t.Helper()
	q, key := signedJob(t, 5)
	p := &fakePlatform{hash: q.ExpectedHash}
	path := filepath.Join(t.TempDir(), "journal.json")
	if e := SaveJSON(path, Journal{Format: 1, Current: q.ExpectedHash, Records: []Record{}}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	policy := func() (Policy, error) { return Policy{Format: 1, Keys: []string{key}, Baseline: q.ExpectedHash}, nil }
	b, e := newBroker(ctx, path, enabled, p, policy, 250*time.Millisecond, 5*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	return b, p, q, cancel
}
func finishFixture(t *testing.T, b *Broker, q protocol.AgentUpgradeJob, proof bool) protocol.AgentUpgradeResult {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if proof {
			b.Healthy(123, q.Release.Manifest.Version)
		}
		r := b.Status(q.ID)
		if r.Outcome != "running" {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("update did not finish")
	return protocol.AgentUpgradeResult{}
}
func TestSignatureBindsEveryReleaseField(t *testing.T) {
	q, _ := signedJob(t, 1)
	if !JobValid(q) {
		t.Fatal("valid signature rejected")
	}
	for _, edit := range []func(*protocol.AgentManifest){func(m *protocol.AgentManifest) { m.Hash = strings.Repeat("d", 64) }, func(m *protocol.AgentManifest) { m.Sequence++ }, func(m *protocol.AgentManifest) { m.Version = "different" }, func(m *protocol.AgentManifest) { m.OS = "linux" }, func(m *protocol.AgentManifest) { m.Expires++ }, func(m *protocol.AgentManifest) { m.Size++ }, func(m *protocol.AgentManifest) { m.Product = "another service" }} {
		r := q.Release
		edit(&r.Manifest)
		if Verify(r, q.PublicKey) {
			t.Fatal("altered signed field accepted")
		}
	}
	if Verify(q.Release, strings.Repeat("0", 64)) {
		t.Fatal("wrong key accepted")
	}
	if Fresh(q.Release.Manifest, time.Now().Add(2*time.Hour)) {
		t.Fatal("expired accepted")
	}
	var m protocol.AgentManifest
	if Decode([]byte(`{"format":1,"unexpected":true}`), &m) == nil {
		t.Fatal("unknown manifest field")
	}
}
func TestBrokerHealthProofCommitAndReplay(t *testing.T) {
	b, p, q, _ := brokerFixture(t, true)
	if b.Submit(q).Outcome != "running" {
		t.Fatal("submit rejected")
	}
	r := finishFixture(t, b, q, true)
	if r.Outcome != "succeeded" || r.Hash != q.Release.Manifest.Hash {
		t.Fatal(r)
	}
	if b.Submit(q) != r {
		t.Fatal("duplicate did not return same outcome")
	}
	other := q
	other.ID = strings.Repeat("d", 32)
	if b.Submit(other).Outcome != "denied" {
		t.Fatal("replayed sequence accepted")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.replaces != 1 || p.restores != 0 {
		t.Fatal("duplicate executed", p.replaces, p.restores)
	}
	if b.Probe().HighWater != 5 {
		t.Fatal("sequence not consumed")
	}
}
func TestBrokerRollsBackFailedStartupAndKeepsSequence(t *testing.T) {
	b, p, q, _ := brokerFixture(t, true)
	p.failStart = true
	b.Submit(q)
	r := finishFixture(t, b, q, true)
	if r.Outcome != "rolled_back" || r.Hash != q.ExpectedHash || b.Probe().HighWater != 5 {
		t.Fatal(r, b.Probe())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.restores != 1 {
		t.Fatal("old binary not restored")
	}
}
func TestBrokerRejectsWrongPeerAndVersion(t *testing.T) {
	b, _, q, _ := brokerFixture(t, true)
	b.Submit(q)
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		b.Healthy(999, q.Release.Manifest.Version)
		b.Healthy(123, "wrong-version")
		time.Sleep(time.Millisecond)
	}
	if r := b.Status(q.ID); r.Outcome != "running" {
		t.Fatal("unauthenticated proof accepted", r)
	}
	r := finishFixture(t, b, q, false)
	if r.Outcome != "recovery_required" {
		t.Fatal("unproved recovery accepted", r)
	}
}
func TestBrokerLocalOptInAndKeyPinRequired(t *testing.T) {
	b, p, q, _ := brokerFixture(t, false)
	if b.Submit(q).Outcome != "denied" {
		t.Fatal("disabled updater executed")
	}
	b.enabled = true
	other, _ := signedJob(t, 6)
	if b.Submit(other).Outcome != "denied" {
		t.Fatal("untrusted key executed")
	}
	q.ExpectedHash = strings.Repeat("e", 64)
	if b.Submit(q).Outcome != "denied" {
		t.Fatal("source mismatch")
	}
	if p.stops != 0 {
		t.Fatal("denial mutated service")
	}
}
func TestBrokerCancelledWorkRestoresWithIPCStillAvailable(t *testing.T) {
	b, _, q, cancel := brokerFixture(t, true)
	b.Submit(q)
	cancel()
	drain := b.Drain()
	r := finishFixture(t, b, q, true)
	if r.Outcome != "rolled_back" {
		t.Fatal(r)
	}
	select {
	case <-drain:
	case <-time.After(time.Second):
		t.Fatal("drain blocked")
	}
	if b.Submit(q).Outcome != "rolled_back" {
		t.Fatal("recovery idempotence")
	}
}
func TestBrokerRecoversInterruptedTransactionWithoutResubmit(t *testing.T) {
	q, key := signedJob(t, 9)
	p := &fakePlatform{hash: q.Release.Manifest.Hash}
	path := filepath.Join(t.TempDir(), "journal.json")
	record := Record{Job: q, Old: q.ExpectedHash, Phase: "replacing", Result: protocol.AgentUpgradeResult{ID: q.ID, Outcome: "running", Hash: q.ExpectedHash, Sequence: 9}}
	if e := SaveJSON(path, Journal{Format: 1, Current: q.ExpectedHash, HighWater: 9, Active: q.ID, Records: []Record{record}}); e != nil {
		t.Fatal(e)
	}
	b, e := newBroker(context.Background(), path, false, p, func() (Policy, error) { return Policy{Keys: []string{key}}, nil }, time.Second, 0)
	if e != nil {
		t.Fatal(e)
	}
	r := finishFixture(t, b, q, true)
	if r.Outcome != "rolled_back" || b.Probe().HighWater != 9 {
		t.Fatal(r)
	}
	if p.replaces != 0 || p.restores != 1 {
		t.Fatal("recovery relaunched candidate")
	}
	raw, _ := os.ReadFile(path)
	var journal Journal
	if Decode(raw, &journal) != nil || journal.Active != "" {
		t.Fatal("recovery not durable")
	}
}
func TestBrokerMissingJournalNeverResetsCounter(t *testing.T) {
	_, e := NewBroker(context.Background(), filepath.Join(t.TempDir(), "absent"), true, &fakePlatform{}, func() (Policy, error) { return Policy{}, nil })
	if e == nil {
		t.Fatal("missing counter silently reset")
	}
}

func TestBrokerDurableFailureDiagnostics(t *testing.T) {
	b, _, q, _ := brokerFixture(t, true)
	b.Submit(q)
	b.fault(q.ID, "stop", syscall.Errno(5))
	b.fault(q.ID, "rollback_stop", syscall.Errno(6))
	finishFixture(t, b, q, true)
	raw, e := os.ReadFile(b.path)
	if e != nil {
		t.Fatal(e)
	}
	var j Journal
	if Decode(raw, &j) != nil {
		t.Fatal("journal corrupt")
	}
	r := j.Records[0]
	if r.InitialFailure != "stop" || r.InitialCode != 5 || r.Failure != "rollback_stop" || r.ErrorCode != 6 {
		t.Fatal("failure context not preserved", r.InitialFailure, r.InitialCode, r.Failure, r.ErrorCode)
	}
}

// msiPlatform is the fake platform for an MSI release: after Replace the
// device runs the packaged agent (AgentHash), and success commits the package.
type msiPlatform struct {
	fakePlatform
	commits int
}

func (p *msiPlatform) Prepare(q protocol.AgentUpgradeJob) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.old, p.next = p.hash, AgentHash(q.Release.Manifest)
	return nil
}
func (p *msiPlatform) Commit(protocol.AgentUpgradeJob) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.commits++
	return nil
}
func (p *msiPlatform) Installer() string { return "msi" }

func TestBrokerMSIReleaseUsesAgentHashAndCommits(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	m := protocol.AgentManifest{Format: 2, Package: "msi", AgentHash: strings.Repeat("e", 64), Product: "OpenRMMAgent", OS: "windows", Architecture: "amd64", Version: "test.3", Sequence: 6, Size: 100, Hash: strings.Repeat("f", 64), KeyID: Digest(public), Issued: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Hour).Unix()}
	key := hex.EncodeToString(public)
	q := protocol.AgentUpgradeJob{ID: strings.Repeat("a", 32), Release: protocol.SignedAgentRelease{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, Message(m)))}, PublicKey: key, ExpectedHash: strings.Repeat("c", 64), ExpiresAt: now.Add(time.Minute).Unix()}
	p := &msiPlatform{fakePlatform: fakePlatform{hash: q.ExpectedHash}}
	path := filepath.Join(t.TempDir(), "journal.json")
	if e := SaveJSON(path, Journal{Format: 1, Current: q.ExpectedHash, Records: []Record{}}); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, e := newBroker(ctx, path, true, p, func() (Policy, error) { return Policy{Format: 1, Keys: []string{key}}, nil }, 250*time.Millisecond, 5*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if s := b.Probe(); s.Installer != "msi" {
		t.Fatal("MSI platform not reported", s)
	}
	if b.Submit(q).Outcome != "running" {
		t.Fatal("submit rejected")
	}
	r := finishFixture(t, b, q, true)
	if r.Outcome != "succeeded" || r.Hash != m.AgentHash {
		t.Fatal("MSI update result", r)
	}
	if b.Probe().CurrentHash != m.AgentHash || p.commits != 1 {
		t.Fatal("installed agent hash or rollback package not recorded", p.commits)
	}
}
