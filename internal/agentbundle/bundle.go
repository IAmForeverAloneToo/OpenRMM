// Package agentbundle carries the signed agent release that scripts/release.ps1
// places into the server build. The server verifies and imports it at start-up,
// so a deployed server always offers the agent built with it.
package agentbundle

import (
	"embed"
	"errors"
	"io/fs"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

//go:embed all:files
var files embed.FS

var ErrIncomplete = errors.New("bundled agent release is incomplete or malformed")

type Bundle struct {
	Release   protocol.SignedAgentRelease
	PublicKey string
	Binary    []byte
}

// Load returns the bundled release. ok is false when the build carries none.
func Load() (Bundle, bool, error) { return load(files) }

func load(fsys fs.FS) (Bundle, bool, error) {
	manifest, e := fs.ReadFile(fsys, "files/release.json")
	if errors.Is(e, fs.ErrNotExist) {
		return Bundle{}, false, nil
	}
	if e != nil {
		return Bundle{}, true, ErrIncomplete
	}
	var b Bundle
	public, e1 := fs.ReadFile(fsys, "files/public.txt")
	// The artifact is the agent MSI; older builds carried the
	// executable. The manifest's format says which one it must be.
	artifact := "files/openrmm-agent.exe"
	if agentupdate.Decode(manifest, &b.Release) == nil && agentupdate.MSI(b.Release.Manifest) {
		artifact = "files/openrmm-agent.msi"
	}
	binary, e2 := fs.ReadFile(fsys, artifact)
	if errors.Join(e1, e2) != nil || len(manifest) > 16384 || len(public) > 256 || int64(len(binary)) > agentupdate.MaxArtifact || agentupdate.Decode(manifest, &b.Release) != nil {
		return Bundle{}, true, ErrIncomplete
	}
	b.PublicKey = strings.TrimSpace(string(public))
	b.Binary = binary
	if !agentupdate.Verify(b.Release, b.PublicKey) || int64(len(binary)) != b.Release.Manifest.Size || agentupdate.Digest(binary) != b.Release.Manifest.Hash {
		return Bundle{}, true, ErrIncomplete
	}
	return b, true, nil
}
