package devices

import (
	"context"
	"crypto/tls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"os"
)

func (s *Service) PollAgentUpgrade(ctx context.Context, state *tls.ConnectionState) (protocol.AgentUpgradeDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.AgentUpgradeDispatch{}, e
	}
	return s.store.DispatchAgentUpgrade(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), s.now())
}
func (s *Service) AgentUpgradeResult(ctx context.Context, state *tls.ConnectionState, r protocol.AgentUpgradeResult) (protocol.HeartbeatReceipt, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.HeartbeatReceipt{}, e
	}
	now := s.now()
	e = s.store.CompleteAgentUpgrade(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), r, now)
	return protocol.HeartbeatReceipt{DeviceID: d.ID, ReceivedAt: now.Unix()}, e
}
func (s *Service) AgentArtifact(ctx context.Context, state *tls.ConnectionState, id string) (storage.AgentRelease, *os.File, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return storage.AgentRelease{}, nil, e
	}
	return s.store.AgentReleaseArtifact(ctx, d.ID, deviceidentity.Fingerprint(state.PeerCertificates[0].Raw), id, s.now())
}
