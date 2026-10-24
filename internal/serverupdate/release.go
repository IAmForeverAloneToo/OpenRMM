// Package serverupdate updates the server from the dashboard.
//
// A server release is a manifest signed with the project key, the same key
// that signs agent releases. It pins the exact image (its content-addressed
// image ID), so a registry account alone cannot change what is installed.
// The server checks for a newer release about once a day and, on request,
// hands it to the updater sidecar, which verifies it again, backs up the
// database and secrets, swaps the image and rolls back if the new version
// does not become healthy.
package serverupdate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentbundle"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
)

const (
	Product  = "OpenRMMServer"
	MaxNotes = 16 * 1024
	// MaxLife bounds how long a signed release can be offered.
	MaxLife = 400 * 24 * time.Hour
)

// Manifest describes one server release.
type Manifest struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	// Image is the repository without tag, such as ghcr.io/owner/openrmm-server.
	Image string `json:"image"`
	// ImageID is the image's content digest (sha256:...), checked after pull.
	ImageID string `json:"image_id"`
	// Digest is the registry manifest digest used to pull (optional for
	// images that are already present).
	Digest  string `json:"digest,omitempty"`
	Notes   string `json:"notes"`
	KeyID   string `json:"key_id"`
	Issued  int64  `json:"issued"`
	Expires int64  `json:"expires"`
}

type Release struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}

var (
	imageName = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-]{1,2}[a-z0-9]+)*)*$`)
	digest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Valid checks a manifest's fields.
func Valid(m Manifest) bool {
	return m.Product == Product && agentupdate.Version(m.Version) && m.Sequence > 0 && m.Sequence <= agentupdate.MaxMSISequence &&
		len(m.Image) <= 255 && imageName.MatchString(m.Image) && digest.MatchString(m.ImageID) && (m.Digest == "" || digest.MatchString(m.Digest)) &&
		len(m.Notes) <= MaxNotes && utf8.ValidString(m.Notes) && agentupdate.Hash(m.KeyID) &&
		m.Issued > 0 && m.Expires > m.Issued && m.Expires-m.Issued <= int64(MaxLife/time.Second)
}

// Fresh reports whether the release may be offered now.
func Fresh(m Manifest, now time.Time) bool {
	return Valid(m) && m.Issued <= now.Add(5*time.Minute).Unix() && now.Unix() < m.Expires
}

// Message is the signed byte string.
func Message(m Manifest) []byte {
	b, _ := json.Marshal(m)
	return append([]byte("OpenRMM server release v1\x00"), b...)
}

// Sign signs a manifest (scripts/release.ps1 through openrmm-release).
func Sign(priv ed25519.PrivateKey, m Manifest) Release {
	return Release{Manifest: m, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Message(m)))}
}

// Verify checks the signature against one of the trusted public keys (hex).
func Verify(r Release, keys []string) bool {
	if !Valid(r.Manifest) {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(r.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, k := range keys {
		raw, e := hex.DecodeString(k)
		if e != nil || len(raw) != ed25519.PublicKeySize || hex.EncodeToString(raw) != k {
			continue
		}
		if agentupdate.Digest(raw) == r.Manifest.KeyID && ed25519.Verify(ed25519.PublicKey(raw), Message(r.Manifest), sig) {
			return true
		}
	}
	return false
}

// ImageRef is what the updater pulls: by registry digest when known.
func ImageRef(m Manifest) string {
	if m.Digest != "" {
		return m.Image + "@" + m.Digest
	}
	return m.Image + "@" + m.ImageID
}

// Current is the running build: the release bundled with it (scripts/
// release.ps1 uses one version and sequence for the server and its agent).
type Current struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	// Keys are the public keys this build trusts for server releases.
	Keys []string `json:"-"`
}

// Running describes this build; extra adds operator keys.
func Running(extra []string) Current {
	c := Current{Version: "development"}
	if b, ok, e := agentbundle.Load(); ok && e == nil {
		c.Version, c.Sequence = b.Release.Manifest.Version, b.Release.Manifest.Sequence
		c.Keys = append(c.Keys, b.PublicKey)
	}
	for _, k := range extra {
		if k = strings.TrimSpace(k); k != "" && len(c.Keys) < 8 {
			c.Keys = append(c.Keys, k)
		}
	}
	return c
}

// Newer reports whether a verified release should be offered to this build.
func (c Current) Newer(r Release, now time.Time) bool {
	return Verify(r, c.Keys) && Fresh(r.Manifest, now) && r.Manifest.Sequence > c.Sequence
}
