package agentupdate

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"os"
	"sync"
	"syscall"
	"time"
)

type Policy struct {
	Format   int      `json:"format"`
	Keys     []string `json:"public_keys"`
	Baseline string   `json:"baseline_sha256"`
	Command  string   `json:"service_command"`
}
type Record struct {
	Job            protocol.AgentUpgradeJob    `json:"job"`
	Result         protocol.AgentUpgradeResult `json:"result"`
	Old            string                      `json:"previous_sha256"`
	Phase          string                      `json:"phase"`
	InitialFailure string                      `json:"initial_failure,omitempty"`
	InitialCode    uint32                      `json:"initial_error_code,omitempty"`
	Failure        string                      `json:"failure,omitempty"`
	ErrorCode      uint32                      `json:"error_code,omitempty"`
	FailureDetail  string                      `json:"failure_detail,omitempty"`
}
type Journal struct {
	Format    int      `json:"format"`
	Current   string   `json:"current_sha256"`
	HighWater int64    `json:"high_water"`
	Active    string   `json:"active"`
	Records   []Record `json:"records"`
}
type Platform interface {
	Current() (string, error)
	Prepare(protocol.AgentUpgradeJob) error
	Stop(context.Context) error
	Replace() error
	Start(context.Context) error
	Restore(string, string) error
	Peer(uint32, string) bool
	Active(string) bool
}
type Broker struct {
	mu                       sync.Mutex
	workers                  sync.WaitGroup
	ctx                      context.Context
	path                     string
	state                    Journal
	enabled, broken, healthy bool
	platform                 Platform
	policy                   func() (Policy, error)
	healthWait, settle       time.Duration
}

func SaveJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = commitJSON(path+".tmp", path)
	}
	return e
}
func NewBroker(ctx context.Context, path string, enabled bool, p Platform, policy func() (Policy, error)) (*Broker, error) {
	return newBroker(ctx, path, enabled, p, policy, 90*time.Second, 10*time.Second)
}
func newBroker(ctx context.Context, path string, enabled bool, p Platform, policy func() (Policy, error), healthWait, settle time.Duration) (*Broker, error) {
	b := &Broker{ctx: ctx, path: path, enabled: enabled, platform: p, policy: policy, healthWait: healthWait, settle: settle}
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 1024*1024 || Decode(raw, &b.state) != nil || b.state.Format != 1 || !Hash(b.state.Current) || b.state.HighWater < 0 || b.state.Records == nil || len(b.state.Records) > 20 {
		return nil, ErrInvalid
	}
	found := b.state.Active == ""
	seen := map[string]bool{}
	for _, r := range b.state.Records {
		if !JobValid(r.Job) || !ResultValid(r.Result) || r.Result.ID != r.Job.ID || !Hash(r.Old) || seen[r.Job.ID] || r.Job.Release.Manifest.Sequence > b.state.HighWater {
			return nil, ErrInvalid
		}
		seen[r.Job.ID] = true
		if r.Job.ID == b.state.Active {
			if r.Old != b.state.Current || (r.Result.Outcome != "running" && r.Result.Outcome != "recovery_required") {
				return nil, ErrInvalid
			}
			switch r.Phase {
			case "prepared", "stopping", "replacing", "checking", "rollback_preparing", "rollback_checking", "complete":
			default:
				return nil, ErrInvalid
			}
			found = true
		} else if r.Phase != "complete" || r.Result.Outcome == "running" || r.Result.Outcome == "recovery_required" {
			return nil, ErrInvalid
		}
	}
	if !found {
		return nil, ErrInvalid
	}
	if _, e = policy(); e != nil {
		return nil, e
	}
	if b.state.Active != "" {
		b.workers.Add(1)
		go func() { defer b.workers.Done(); b.rollback(b.state.Active) }()
	}
	return b, nil
}
func (b *Broker) save() bool {
	if SaveJSON(b.path, b.state) != nil {
		b.broken = true
		return false
	}
	return true
}
func (b *Broker) record(id string) *Record {
	for i := range b.state.Records {
		if b.state.Records[i].Job.ID == id {
			return &b.state.Records[i]
		}
	}
	return nil
}

// Revision identifies the agent updater's behaviour for the fleet view. Raise
// it whenever a release changes the updater, so devices still running an older
// one are flagged for a local reinstall. 2: early-disconnect pipe reset and
// shape-based service command check. 3: accepts the single LocalSystem
// agent (and only that). 4: runs inside the agent as an on-demand helper
// and installs signed MSI packages.
const Revision = 4

func (b *Broker) Probe() protocol.AgentUpgradeSupport {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := protocol.AgentUpgradeSupport{Broker: "disabled", CurrentHash: b.state.Current, HighWater: b.state.HighWater, KeyIDs: []string{}, UpdaterRevision: Revision}
	if i, ok := b.platform.(interface{ Installer() string }); ok {
		s.Installer = i.Installer()
	}
	p, e := b.policy()
	if e != nil || b.broken {
		s.Broker = "recovery_required"
		return s
	}
	for _, k := range p.Keys {
		raw, ok := publicKey(k)
		if ok {
			s.KeyIDs = append(s.KeyIDs, Digest(raw))
		}
	}
	if b.state.Active != "" {
		s.Broker = "busy"
	}
	if b.enabled && b.state.Active == "" {
		s.Broker = "enabled"
	}
	return s
}
func (b *Broker) Status(id string) protocol.AgentUpgradeResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r := b.record(id); r != nil {
		return r.Result
	}
	return protocol.AgentUpgradeResult{ID: id, Outcome: "unknown"}
}
func (b *Broker) Submit(q protocol.AgentUpgradeJob) protocol.AgentUpgradeResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	denied := protocol.AgentUpgradeResult{ID: q.ID, Outcome: "denied"}
	if r := b.record(q.ID); r != nil {
		old, _ := json.Marshal(r.Job)
		now, _ := json.Marshal(q)
		if string(old) != string(now) {
			return denied
		}
		return r.Result
	}
	p, e := b.policy()
	if e != nil || !b.enabled || b.broken || b.ctx.Err() != nil || b.state.Active != "" || !JobValid(q) || time.Now().Unix() >= q.ExpiresAt || !Fresh(q.Release.Manifest, time.Now()) || q.Release.Manifest.Sequence <= b.state.HighWater || q.ExpectedHash != b.state.Current {
		return denied
	}
	pinned := false
	for _, k := range p.Keys {
		if k == q.PublicKey {
			pinned = true
		}
	}
	if !pinned {
		return denied
	}
	hash, e := b.platform.Current()
	if e != nil || hash != b.state.Current {
		return denied
	}
	if e = b.platform.Prepare(q); e != nil {
		return denied
	}
	if len(b.state.Records) >= 20 {
		b.state.Records = b.state.Records[1:]
	}
	result := protocol.AgentUpgradeResult{ID: q.ID, Outcome: "running", Hash: q.ExpectedHash, Sequence: q.Release.Manifest.Sequence}
	b.state.HighWater = q.Release.Manifest.Sequence
	b.state.Active = q.ID
	b.healthy = false
	b.state.Records = append(b.state.Records, Record{Job: q, Old: q.ExpectedHash, Result: result, Phase: "prepared"})
	if !b.save() {
		return denied
	}
	b.workers.Add(1)
	go func() { defer b.workers.Done(); b.apply(q.ID) }()
	return result
}
func (b *Broker) phase(id, phase string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.record(id)
	if r == nil || b.broken {
		return false
	}
	r.Phase = phase
	b.healthy = false
	return b.save()
}
func (b *Broker) Healthy(pid uint32, version string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.record(b.state.Active)
	if r == nil {
		return
	}
	hash := AgentHash(r.Job.Release.Manifest)
	if r.Phase == "rollback_checking" {
		hash = r.Old
	} else if r.Phase != "checking" || version != r.Job.Release.Manifest.Version {
		return
	}
	if b.platform.Peer(pid, hash) {
		b.healthy = true
	}
}
func (b *Broker) waitHealthy(hash string, recovery bool) bool {
	waitCtx := b.ctx
	if recovery {
		waitCtx = context.Background()
	}
	start := time.Now()
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for time.Since(start) < b.healthWait {
		b.mu.Lock()
		healthy := b.healthy && !b.broken
		b.mu.Unlock()
		if healthy && time.Since(start) >= b.settle && b.platform.Active(hash) {
			return true
		}
		select {
		case <-waitCtx.Done():
			return false
		case <-timer.C:
		}
	}
	return false
}

// Persist only fixed operation labels and OS error numbers, never paths,
// command lines, credentials or arbitrary exception text.
type operationError struct {
	operation string
	err       error
}

func (e operationError) Error() string { return e.operation }
func (e operationError) Unwrap() error { return e.err }
func operationFailure(operation string, e error) error {
	return operationError{operation: operation, err: e}
}
func (b *Broker) fault(id, operation string, e error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.record(id)
	if r == nil {
		return
	}
	var code syscall.Errno
	_ = errors.As(e, &code)
	if r.InitialFailure == "" {
		r.InitialFailure = operation
		r.InitialCode = uint32(code)
	}
	var detail operationError
	if errors.As(e, &detail) {
		r.FailureDetail = detail.operation
	} else {
		r.FailureDetail = ""
	}
	r.Failure = operation
	r.ErrorCode = uint32(code)
	b.save()
}
func (b *Broker) finish(id, outcome, hash string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.record(id)
	if r == nil {
		return
	}
	if outcome == "recovery_required" {
		observed, e := b.platform.Current()
		hash = ""
		if e == nil && Hash(observed) {
			hash = observed
		}
	}
	r.Result.Outcome = outcome
	r.Result.Hash = hash
	r.Phase = "complete"
	if outcome == "succeeded" {
		b.state.Current = hash
	}
	if outcome == "recovery_required" {
		b.broken = true
	} else {
		b.state.Active = ""
	}
	b.save()
}
func (b *Broker) apply(id string) {
	b.mu.Lock()
	r := *b.record(id)
	b.mu.Unlock()
	if !b.phase(id, "stopping") {
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, 20*time.Second)
	e := b.platform.Stop(ctx)
	cancel()
	if e != nil {
		b.fault(id, "stop", e)
		b.rollback(id)
		return
	}
	if !b.phase(id, "replacing") {
		return
	}
	if e := b.platform.Replace(); e != nil {
		b.fault(id, "replace", e)
		b.rollback(id)
		return
	}
	if !b.phase(id, "checking") {
		return
	}
	ctx, cancel = context.WithTimeout(b.ctx, 20*time.Second)
	e = b.platform.Start(ctx)
	cancel()
	if e != nil {
		b.fault(id, "start", e)
		b.rollback(id)
		return
	}
	if !b.waitHealthy(AgentHash(r.Job.Release.Manifest), false) {
		b.fault(id, "health", nil)
		b.rollback(id)
		return
	}
	// A platform that keeps a rollback package records the release that is
	// now installed; failing to do so does not undo a healthy update.
	if c, ok := b.platform.(interface {
		Commit(protocol.AgentUpgradeJob) error
	}); ok {
		_ = c.Commit(r.Job)
	}
	b.finish(id, "succeeded", AgentHash(r.Job.Release.Manifest))
}
func (b *Broker) rollback(id string) {
	b.mu.Lock()
	p := b.record(id)
	if p == nil {
		b.mu.Unlock()
		return
	}
	old, newHash := p.Old, AgentHash(p.Job.Release.Manifest)
	b.mu.Unlock()
	if !b.phase(id, "rollback_preparing") {
		return
	}
	// Recovery runs even when local update opt-in has since been disabled. It
	// restores only the journal's previously trusted bytes, never another release.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	e := b.platform.Stop(ctx)
	cancel()
	if e != nil {
		b.fault(id, "rollback_stop", e)
		b.finish(id, "recovery_required", old)
		return
	}
	e = b.platform.Restore(old, newHash)
	if e != nil {
		b.fault(id, "restore", e)
		b.finish(id, "recovery_required", old)
		return
	}
	if !b.phase(id, "rollback_checking") {
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	e = b.platform.Start(ctx)
	cancel()
	if e != nil {
		b.fault(id, "rollback_start", e)
		b.finish(id, "recovery_required", old)
		return
	}
	if !b.waitHealthy(old, true) {
		b.fault(id, "rollback_health", nil)
		b.finish(id, "recovery_required", old)
		return
	}
	b.finish(id, "rolled_back", old)
}

// Idle reports that no update or recovery is in progress. A transaction that
// needs local recovery counts as idle: nothing more will happen to it here.
func (b *Broker) Idle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state.Active == "" || b.broken
}

// Drain prevents new submissions while keeping IPC available for recovery's
// authenticated health proof. The service waits with SCM checkpoints.
func (b *Broker) Drain() <-chan struct{} {
	b.mu.Lock()
	b.enabled = false
	b.mu.Unlock()
	done := make(chan struct{})
	go func() { b.workers.Wait(); close(done) }()
	return done
}
