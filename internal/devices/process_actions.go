package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollProcessAction(ctx context.Context, state *tls.ConnectionState) (protocol.ProcessDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.ProcessDispatch{}, e
	}
	return s.store.DispatchProcessAction(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) ProcessActionResult(ctx context.Context, state *tls.ConnectionState, result protocol.ProcessResult) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.CompleteProcessAction(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), result, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
