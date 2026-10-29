package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A busy server is not a failed download: the agent waits and asks again
// instead of reporting the update failed, which would pause the rollout.
func TestAgentReleaseDownloadBusy(t *testing.T) {
	busy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer busy.Close()
	s := &heartbeatSession{transport: busy.Client().Transport.(*http.Transport)}
	s.value.DeviceURL = busy.URL
	path := filepath.Join(t.TempDir(), "release.msi")
	e := s.downloadAgentRelease(context.Background(), protocol.AgentUpgradeJob{ID: strings.Repeat("a", 32)}, path)
	if !errors.Is(e, errDownloadBusy) {
		t.Fatal("busy server not recognised", e)
	}
	if _, e = os.Stat(path); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("a busy reply left a release file", e)
	}
}
