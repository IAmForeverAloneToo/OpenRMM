package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollScriptRun(ctx context.Context, state *tls.ConnectionState) (protocol.ScriptDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.ScriptDispatch{}, e
	}
	return s.store.DispatchScriptRun(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) ScriptRunResult(ctx context.Context, state *tls.ConnectionState, r protocol.ScriptResult) (protocol.ScriptReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.ScriptReceipt{}, e
	}
	now := s.now()
	cancel, e := s.store.UpdateScriptRun(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), r, now)
	return protocol.ScriptReceipt{DeviceID: d.ID, ReceivedAt: now.Unix(), Cancel: cancel}, e
}
