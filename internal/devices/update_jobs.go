package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func (s *Service) PollUpdateJob(ctx context.Context, state *tls.ConnectionState) (protocol.UpdateDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.UpdateDispatch{}, e
	}
	return s.store.DispatchUpdateJob(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) UpdateJobProgress(ctx context.Context, state *tls.ConnectionState, r protocol.UpdateProgress) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.RecordUpdateProgress(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), r, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
