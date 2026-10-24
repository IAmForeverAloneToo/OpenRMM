package devices

import (
	"context"
	"crypto/tls"
	"io"
	"os"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Evidence collection calls from agents; every call repeats the
// device's certificate authentication and binds the job to that device.

func fingerprint(state *tls.ConnectionState) string {
	return deviceidentity.Fingerprint(state.PeerCertificates[0].Raw)
}

func (s *Service) PollEvidence(ctx context.Context, state *tls.ConnectionState) (protocol.EvidenceDispatch, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.EvidenceDispatch{}, e
	}
	return s.store.DispatchEvidence(ctx, d.ID, fingerprint(state), s.now())
}
func (s *Service) StartEvidence(ctx context.Context, state *tls.ConnectionState, job string, v protocol.EvidenceStart) (protocol.EvidenceProgress, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return protocol.EvidenceProgress{}, e
	}
	return s.store.StartEvidence(ctx, d.ID, fingerprint(state), job, v, s.now())
}
func (s *Service) EvidenceChunk(ctx context.Context, state *tls.ConnectionState, job string, index int64, hash string, body io.Reader) error {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return e
	}
	return s.store.PutEvidenceChunk(ctx, d.ID, fingerprint(state), job, index, hash, body, s.now())
}
func (s *Service) FinishEvidence(ctx context.Context, state *tls.ConnectionState, job string, v protocol.EvidenceFinish) error {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return e
	}
	return s.store.FinishEvidence(ctx, d.ID, fingerprint(state), job, v, s.now())
}

// DropPayload opens the file a drop action sends to this device.
func (s *Service) DropPayload(ctx context.Context, state *tls.ConnectionState, job string) (*os.File, int64, error) {
	d, e := s.Authenticate(ctx, state)
	if e != nil {
		return nil, 0, e
	}
	return s.store.DropPayload(ctx, d.ID, fingerprint(state), job, s.now())
}
