package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollServiceAction(ctx context.Context, state *tls.ConnectionState) (protocol.ServiceDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.ServiceDispatch{}, e
	}
	return s.store.DispatchServiceAction(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) ServiceActionResult(ctx context.Context, state *tls.ConnectionState, result protocol.ServiceResult) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.CompleteServiceAction(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), result, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
