package agent

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const heartbeatPath = "/api/v1/agent/heartbeat"

// errInvalidDispatch marks a dispatch that failed local validation. It is
// discarded (never executed) and the worker backs off like any other failure.
var errInvalidDispatch = errors.New("invalid dispatch discarded")

// pacer spaces out a job worker's polls after failures. Workers never stop
// because of a server response; only cancellation ends them. A revocation
// pauses them through the session gate (no network traffic) while the
// heartbeat loop re-checks hourly.
type pacer struct{ backoff time.Duration }

func (p *pacer) next(err error, normal time.Duration) time.Duration {
	switch {
	case err == nil:
		p.backoff = 0
		return normal
	case errors.Is(err, ErrDeviceRevoked), errors.Is(err, ErrDeviceThrottled):
		return time.Minute
	}
	limit := time.Minute
	if errors.Is(err, ErrRequestRejected) || errors.Is(err, ErrDeviceRejected) {
		limit = 5 * time.Minute
	}
	p.backoff = min(max(p.backoff*2, normal), limit)
	return p.backoff
}

// call sends one device request through the session's current mTLS client.
// While the identity is known to be revoked, only the heartbeat reaches the
// server; every other request fails locally until a heartbeat succeeds again.
// callWithTimeout is call with its own deadline, for requests that move more
// data than the session timeout allows (evidence).
func (s *heartbeatSession) callWithTimeout(ctx context.Context, path string, input, output any, timeout time.Duration) error {
	if s.revoked.Load() {
		return ErrDeviceRevoked
	}
	s.transportMu.RLock()
	transport, origin := s.transport, s.value.DeviceURL
	s.transportMu.RUnlock()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	err := requestWithClient(ctx, client, origin, http.MethodPost, path, input, output)
	if errors.Is(err, ErrDeviceRevoked) {
		s.revoked.Store(true)
	}
	return err
}

func (s *heartbeatSession) call(ctx context.Context, path string, input, output any) error {
	if s.revoked.Load() && path != heartbeatPath {
		return ErrDeviceRevoked
	}
	s.transportMu.RLock()
	client, origin := s.client, s.value.DeviceURL
	s.transportMu.RUnlock()
	err := requestWithClient(ctx, client, origin, http.MethodPost, path, input, output)
	switch {
	case errors.Is(err, ErrDeviceRevoked):
		s.revoked.Store(true)
	case err == nil && path == heartbeatPath:
		s.revoked.Store(false)
	}
	return err
}
