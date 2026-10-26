package agentupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"os"
	"strings"
	"time"
)

const MaxArtifact = 32 * 1024 * 1024

// MaxLife bounds how long a signed agent release stays valid. Public releases
// are signed for a year, so installers and updates keep working between
// releases; the expiry still limits how long an old release can be replayed.
const MaxLife = 366 * 24 * time.Hour
const MaxIPC = 32768

var Capability = protocol.Capability{Name: "agent_updates", Version: 1}
var ErrInvalid = errors.New("agent release or updater state invalid/unavailable")

func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Hash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func Version(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_+", c)) {
			return false
		}
	}
	return true
}
func Valid(m protocol.AgentManifest) bool {
	switch {
	case m.Format == 1 && m.Package == "" && m.AgentHash == "":
	case m.Format == 2 && m.Package == "msi" && Hash(m.AgentHash):
	default:
		return false
	}
	return m.Product == "OpenRMMAgent" && m.OS == "windows" && m.Architecture == "amd64" && Version(m.Version) && m.Sequence > 0 && m.Sequence <= MaxMSISequence && m.Size > 0 && m.Size <= MaxArtifact && Hash(m.Hash) && Hash(m.KeyID) && m.Issued > 0 && m.Expires > m.Issued && m.Expires-m.Issued <= int64(MaxLife/time.Second)
}

// Build-time trust, set with -ldflags -X by scripts/build.ps1 and
// scripts/release.ps1: the public keys whose signatures this agent accepts
// (comma-separated hex) and the release sequence it was built for, which is
// the floor of its replay counter. A build without keys accepts no update.
var PinnedKeys, ReleaseSequence string

// Keys returns the valid, distinct pinned keys (at most eight).
func Keys() []string {
	out := []string{}
	seen := map[string]bool{}
	for _, k := range strings.Split(PinnedKeys, ",") {
		k = strings.TrimSpace(k)
		if _, ok := publicKey(k); ok && !seen[k] && len(out) < 8 {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// SequenceFloor is the release sequence built into this agent (0 if none).
func SequenceFloor() int64 {
	var n int64
	for _, c := range ReleaseSequence {
		if c < '0' || c > '9' || n > MaxMSISequence {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}

// JournalSupport describes update support from the journal alone, for when
// no update helper is running.
func JournalSupport(path string) protocol.AgentUpgradeSupport {
	keys := Keys()
	s := protocol.AgentUpgradeSupport{Broker: "disabled", CurrentHash: strings.Repeat("0", 64), KeyIDs: []string{}, UpdaterRevision: Revision, Installer: "msi"}
	for _, k := range keys {
		raw, _ := publicKey(k)
		s.KeyIDs = append(s.KeyIDs, Digest(raw))
	}
	var j Journal
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 1024*1024 || Decode(raw, &j) != nil || j.Format != 1 || !Hash(j.Current) || j.HighWater < 0 {
		if len(keys) > 0 {
			s.Broker = "recovery_required"
		}
		return s
	}
	s.CurrentHash, s.HighWater = j.Current, j.HighWater
	switch {
	case len(keys) == 0:
	case j.Active == "":
		s.Broker = "enabled"
	default:
		s.Broker = "busy"
		for _, r := range j.Records {
			if r.Job.ID == j.Active && r.Result.Outcome == "recovery_required" {
				s.Broker = "recovery_required"
			}
		}
	}
	return s
}

// JournalStatus reports a job's result from the journal alone.
func JournalStatus(path, id string) (protocol.AgentUpgradeResult, error) {
	var j Journal
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 1024*1024 || Decode(raw, &j) != nil {
		return protocol.AgentUpgradeResult{}, ErrInvalid
	}
	for _, r := range j.Records {
		if r.Job.ID == id {
			return r.Result, nil
		}
	}
	return protocol.AgentUpgradeResult{ID: id, Outcome: "unknown"}, nil
}

// MaxMSISequence keeps the sequence usable as the build field of a Windows
// Installer ProductVersion (1.0.<sequence>), whose limit is 65535.
const MaxMSISequence = 65535

// MSI reports whether a release is a Windows Installer package (format 2).
func MSI(m protocol.AgentManifest) bool { return m.Format == 2 && m.Package == "msi" }

// AgentHash is the hash a device reports once it runs this release: the
// installed executable for MSI releases, the artifact itself for format 1.
func AgentHash(m protocol.AgentManifest) string {
	if MSI(m) {
		return m.AgentHash
	}
	return m.Hash
}
func Fresh(m protocol.AgentManifest, now time.Time) bool {
	return Valid(m) && m.Issued <= now.Add(5*time.Minute).Unix() && now.Unix() < m.Expires
}
func Message(m protocol.AgentManifest) []byte {
	b, _ := json.Marshal(m)
	return append([]byte("OpenRMM agent release v1\x00"), b...)
}
func Verify(r protocol.SignedAgentRelease, public string) bool {
	key, canonical := publicKey(public)
	sig, se := base64.StdEncoding.DecodeString(r.Signature)
	return canonical && se == nil && len(key) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && Valid(r.Manifest) && Digest(key) == r.Manifest.KeyID && ed25519.Verify(ed25519.PublicKey(key), Message(r.Manifest), sig)
}
func ReleaseID(r protocol.SignedAgentRelease) string { b, _ := json.Marshal(r); return Digest(b) }
func JobValid(q protocol.AgentUpgradeJob) bool {
	return protocol.ValidID(q.ID) && Hash(q.ExpectedHash) && q.ExpectedHash != AgentHash(q.Release.Manifest) && q.ExpiresAt > 0 && Verify(q.Release, q.PublicKey)
}
func ResultValid(r protocol.AgentUpgradeResult) bool {
	if !protocol.ValidID(r.ID) || r.Sequence < 0 {
		return false
	}
	switch r.Outcome {
	case "running", "succeeded", "rolled_back":
		return Hash(r.Hash)
	case "denied", "unknown", "failed", "recovery_required":
		return r.Hash == "" || Hash(r.Hash)
	}
	return false
}
func SupportValid(s protocol.AgentUpgradeSupport) bool {
	if s.KeyIDs == nil || len(s.KeyIDs) > 8 || s.HighWater < 0 || !Hash(s.CurrentHash) || s.UpdaterRevision < 0 || s.UpdaterRevision > 1000 || s.Installer != "" && s.Installer != "msi" {
		return false
	}
	switch s.Broker {
	case "missing", "denied", "disabled", "enabled", "busy", "recovery_required":
	default:
		return false
	}
	seen := map[string]bool{}
	for _, k := range s.KeyIDs {
		if !Hash(k) || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}
func FileHash(path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	return ReaderHash(f)
}
func ReaderHash(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, MaxArtifact+1))
	if e != nil || n > MaxArtifact {
		return "", 0, ErrInvalid
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func Inspect(path string, m protocol.AgentManifest) error {
	hash, size, e := FileHash(path)
	if e != nil || hash != m.Hash || size != m.Size {
		return ErrInvalid
	}
	if MSI(m) {
		// A Windows Installer package is an OLE compound document. Windows
		// Installer itself validates the rest; the signature binds the bytes.
		f, e := os.Open(path)
		if e != nil {
			return ErrInvalid
		}
		defer f.Close()
		var magic [8]byte
		if _, e = io.ReadFull(f, magic[:]); e != nil || magic != [8]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1} {
			return ErrInvalid
		}
		return nil
	}
	p, e := pe.Open(path)
	if e != nil {
		return ErrInvalid
	}
	defer p.Close()
	if p.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || p.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || p.Characteristics&pe.IMAGE_FILE_DLL != 0 {
		return ErrInvalid
	}
	if _, ok := p.OptionalHeader.(*pe.OptionalHeader64); !ok {
		return ErrInvalid
	}
	return nil
}

type Client interface {
	Probe(context.Context) (protocol.AgentUpgradeSupport, error)
	Submit(context.Context, protocol.AgentUpgradeJob) (protocol.AgentUpgradeResult, error)
	Status(context.Context, string) (protocol.AgentUpgradeResult, error)
	Healthy(context.Context, string) error
}
type Module struct {
	Client Client
	Hash   string
}

func (Module) Capability() protocol.Capability { return Capability }
func (m Module) Collect(ctx context.Context) (json.RawMessage, error) {
	s, e := m.Client.Probe(ctx)
	if e != nil {
		return nil, e
	}
	s.CurrentHash = m.Hash
	if !SupportValid(s) {
		return nil, ErrInvalid
	}
	return json.Marshal(s)
}
func Normalize(r protocol.FeatureReport) (protocol.FeatureReport, error) {
	if r.Capability != Capability {
		return r, features.ErrReport
	}
	switch r.Status {
	case "disabled", "unsupported", "failed":
		if len(r.Data) != 0 {
			return r, features.ErrReport
		}
	case "ok":
		var s protocol.AgentUpgradeSupport
		if Decode(r.Data, &s) != nil || !SupportValid(s) {
			return r, features.ErrReport
		}
	default:
		return r, features.ErrReport
	}
	return r, nil
}

func publicKey(s string) ([]byte, bool) {
	b, e := hex.DecodeString(s)
	return b, e == nil && len(b) == ed25519.PublicKeySize && hex.EncodeToString(b) == s
}
