package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentbundle"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

// bundledRelease is the signed release built into this server (loaded and
// verified once).
var bundledRelease = sync.OnceValues(func() (protocol.SignedAgentRelease, bool) {
	b, ok, e := agentbundle.Load()
	return b.Release, ok && e == nil
})

// importBundledRelease adds the signed agent release carried by this server
// build to the release library. It never blocks start-up: problems are logged
// and the existing library is left unchanged.
func importBundledRelease(ctx context.Context, store *storage.Store, logger *slog.Logger) {
	b, ok, e := agentbundle.Load()
	if !ok {
		return
	}
	if e != nil {
		logger.Error("bundled agent release is invalid; not imported")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	added, e := importBundle(ctx, store, b, time.Now())
	switch {
	case e != nil:
		logger.Warn("bundled agent release not imported; it may have expired or the release library may be full (withdraw unused releases)", "version", b.Release.Manifest.Version)
	case added:
		logger.Info("bundled agent release imported", "version", b.Release.Manifest.Version, "sequence", b.Release.Manifest.Sequence)
	}
}

func importBundle(ctx context.Context, store *storage.Store, b agentbundle.Bundle, now time.Time) (bool, error) {
	f, e := store.NewAgentReleaseTemp()
	if e != nil {
		return false, e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(b.Binary)
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return false, errors.Join(errors.New("cannot stage bundled release"), e)
	}
	return store.ImportBundledAgentRelease(ctx, b.Release, b.PublicKey, f.Name(), now)
}
