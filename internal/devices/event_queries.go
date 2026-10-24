package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollEventQuery(ctx context.Context, state *tls.ConnectionState) (protocol.EventDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.EventDispatch{}, e
	}
	return s.store.DispatchEventQuery(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) EventQueryResult(ctx context.Context, state *tls.ConnectionState, r protocol.EventResult) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.CompleteEventQuery(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), r, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
