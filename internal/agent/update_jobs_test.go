package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeUpdateAdapter struct {
	submits, statuses int
	q                 protocol.UpdateJob
}

func (a *fakeUpdateAdapter) Probe(context.Context) (protocol.UpdateSupport, error) {
	return protocol.UpdateSupport{Broker: "available"}, nil
}
func (a *fakeUpdateAdapter) Submit(_ context.Context, q protocol.UpdateJob) (protocol.UpdateProgress, error) {
	a.submits++
	a.q = q
	return windowsupdate.Failure(q, "ok"), nil
}
func (a *fakeUpdateAdapter) Status(context.Context, string) (protocol.UpdateProgress, error) {
	a.statuses++
	return windowsupdate.Failure(a.q, "ok"), nil
}
func TestUpdateResultRetryAndRestartNeverResubmit(t *testing.T) {
	for _, restarted := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		path := t.TempDir()
		q := protocol.UpdateJob{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Action: "scan", ExpiresAt: time.Now().Add(time.Minute).Unix()}
		a := &fakeUpdateAdapter{q: q}
		polls, sends := 0, 0
		if restarted {
			b, _ := json.Marshal(q)
			if os.WriteFile(filepath.Join(path, "update-job.json"), b, 0600) != nil {
				t.Fatal("fixture")
			}
		}
		runUpdateJobs(ctx, path, a, func(context.Context) (protocol.UpdateDispatch, error) {
			polls++
			if polls > 1 || restarted {
				cancel()
				return protocol.UpdateDispatch{}, nil
			}
			return protocol.UpdateDispatch{Job: &q}, nil
		}, func(context.Context, protocol.UpdateProgress) error {
			sends++
			if sends == 1 {
				return errors.New("outage")
			}
			return nil
		}, func(context.Context, time.Duration) bool { return ctx.Err() == nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
		cancel()
		want := 1
		if restarted {
			want = 0
		}
		if a.submits != want || sends != 2 {
			t.Fatal("replayed update or lost result retry", a.submits, sends)
		}
		if _, e := os.Stat(filepath.Join(path, "update-job.json")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("acknowledged terminal journal retained")
		}
	}
}
