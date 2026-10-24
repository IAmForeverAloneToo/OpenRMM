package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollFile(ctx context.Context, state *tls.ConnectionState) (protocol.FileDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.FileDispatch{}, e
	}
	return s.store.DispatchFile(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) FileResult(ctx context.Context, state *tls.ConnectionState, r protocol.FileResult) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.CompleteFile(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), r, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
