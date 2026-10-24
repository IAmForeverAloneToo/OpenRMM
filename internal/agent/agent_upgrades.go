package agent

import (
	"context"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type agentUpgradeJournal struct {
	Job   protocol.AgentUpgradeJob `json:"job"`
	Phase string                   `json:"phase"`
}

func (s *heartbeatSession) pollAgentUpgrade(ctx context.Context) (protocol.AgentUpgradeDispatch, error) {
	var out protocol.AgentUpgradeDispatch
	e := s.call(ctx, "/api/v1/agent/agent-upgrades/poll", struct{}{}, &out)
	return out, e
}
func (s *heartbeatSession) downloadAgentRelease(ctx context.Context, q protocol.AgentUpgradeJob, path string) error {
	s.transportMu.RLock()
	transport, origin := s.transport, s.value.DeviceURL
	s.transportMu.RUnlock()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(origin, "/")+"/api/v1/agent/agent-upgrades/"+q.ID+"/artifact", nil)
	if e != nil {
		return e
	}
	response, e := client.Do(request)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength != q.Release.Manifest.Size {
		return agentupdate.ErrInvalid
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := io.Copy(f, io.LimitReader(response.Body, q.Release.Manifest.Size+1))
	if e == nil && n != q.Release.Manifest.Size {
		e = agentupdate.ErrInvalid
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = agentupdate.Inspect(path, q.Release.Manifest)
	}
	return e
}

// releaseFile names the downloaded artifact; the helper reads MSI packages
// from this name in the agent's state folder.
func releaseFile(q protocol.AgentUpgradeJob) string {
	if agentupdate.MSI(q.Release.Manifest) {
		return "agent-release-" + q.ID + ".msi"
	}
	return "agent-release-" + q.ID + ".exe"
}
func (s *heartbeatSession) runAgentUpgrades(ctx context.Context, state, hash string, local agentupdate.Client, logger *slog.Logger) {
	journalPath := filepath.Join(state, "agent-upgrade.json")
	var pending *agentUpgradeJournal
	var result *protocol.AgentUpgradeResult
	if raw, e := readLimited(journalPath, agentupdate.MaxIPC); e == nil {
		var v agentUpgradeJournal
		if agentupdate.Decode(raw, &v) != nil || !agentupdate.JobValid(v.Job) || (v.Phase != "received" && v.Phase != "submitting") {
			logger.Error("agent update journal needs local inspection")
			return
		}
		pending = &v
		if v.Phase != "submitting" {
			r := protocol.AgentUpgradeResult{ID: v.Job.ID, Outcome: "unknown", Hash: hash}
			result = &r
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		if _, stat := os.Stat(journalPath); !errors.Is(stat, os.ErrNotExist) {
			logger.Error("agent update journal unavailable")
			return
		}
	}
	var pace pacer
	for ctx.Err() == nil {
		var failure error
		if result != nil {
			e := s.send(ctx, "/api/v1/agent/agent-upgrades/result", *result)
			if e == nil || errors.Is(e, ErrRequestRejected) {
				if pending != nil {
					_ = os.Remove(filepath.Join(state, releaseFile(pending.Job)))
				}
				_ = os.Remove(journalPath)
				result = nil
				pending = nil
			} else {
				failure = e
			}
		}
		if pending != nil && result == nil {
			if time.Now().Unix() > pending.Job.ExpiresAt+600 {
				r := protocol.AgentUpgradeResult{ID: pending.Job.ID, Outcome: "unknown", Hash: hash}
				result = &r
				continue
			}
			r, e := local.Status(ctx, pending.Job.ID)
			if e == nil && agentupdate.ResultValid(r) && r.ID == pending.Job.ID && r.Outcome != "running" {
				result = &r
				continue
			}
		}
		if pending == nil {
			dispatch, e := s.pollAgentUpgrade(ctx)
			failure = e
			if e == nil && dispatch.Job != nil && !agentupdate.JobValid(*dispatch.Job) {
				logger.Error("invalid agent upgrade discarded")
				failure = errInvalidDispatch
			} else if e == nil && dispatch.Job != nil {
				q := *dispatch.Job
				pending = &agentUpgradeJournal{Job: q, Phase: "received"}
				if agentupdate.SaveJSON(journalPath, pending) != nil {
					return
				}
				failure := protocol.AgentUpgradeResult{ID: q.ID, Outcome: "denied", Hash: hash}
				cap, e := local.Probe(ctx)
				trusted := false
				for _, k := range cap.KeyIDs {
					if k == q.Release.Manifest.KeyID {
						trusted = true
					}
				}
				if e != nil || !trusted || cap.Broker != "enabled" || q.ExpectedHash != hash || !agentupdate.Fresh(q.Release.Manifest, time.Now()) || time.Now().Unix() >= q.ExpiresAt {
					result = &failure
					continue
				}
				path := filepath.Join(state, releaseFile(q))
				downloadCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				e = s.downloadAgentRelease(downloadCtx, q, path)
				cancel()
				if e != nil {
					failure.Outcome = "failed"
					result = &failure
					continue
				}
				pending.Phase = "submitting"
				if agentupdate.SaveJSON(journalPath, pending) != nil {
					return
				}
				r, e := local.Submit(ctx, q)
				if e == nil && agentupdate.ResultValid(r) && r.ID == q.ID && r.Outcome != "running" {
					result = &r
				}
				continue
			}
		}
		if !waitContext(ctx, pace.next(failure, 5*time.Second)) {
			return
		}
	}
}
