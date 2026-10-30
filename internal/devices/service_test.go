package devices

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func fixture(t *testing.T) (*Service, *storage.Store, string, *time.Time) {
	t.Helper()
	root := t.TempDir()
	store, err := storage.Open(context.Background(), filepath.Join(root, "data", "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	path := filepath.Join(root, "secrets", "device-ca", "authority.pem")
	service, err := New(context.Background(), store, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	return service, store, path, &now
}
func request(t *testing.T, token string) protocol.Enrollment {
	t.Helper()
	key, err := deviceidentity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := deviceidentity.CSR(key)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Enrollment{Token: token, CSR: csr, Hostname: "Windows test", OS: "windows", Architecture: "amd64"}
}
func state(t *testing.T, credential protocol.Credential) *tls.ConnectionState {
	t.Helper()
	cert, err := deviceidentity.ParseCertificate(credential.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := deviceidentity.ParseCertificate(credential.DeviceCA)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, ca}}}
}
func TestEnrollmentExpiryReuseAndConcurrentConsumption(t *testing.T) {
	service, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, err := service.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := request(t, token)
	*now = now.Add(SingleTokenLifetime)
	if _, err := service.Enroll(ctx, input, "peer"); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("expired token accepted")
	}
	token, _, err = service.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input.Token = token
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := service.Enroll(ctx, input, "peer"); results <- err }()
	}
	close(start)
	wg.Wait()
	success, failure := 0, 0
	for index := 0; index < 2; index++ {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, storage.ErrAuthentication) {
			failure++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || failure != 1 {
		t.Fatal("concurrent token use did not create exactly one device")
	}
	if _, err := service.Enroll(ctx, input, "peer"); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("used token accepted")
	}
	list, err := store.Devices(ctx)
	if err != nil || len(list) != 1 {
		t.Fatal("incorrect enrolled device count")
	}
}
func TestCertificateRenewalOverlapExpiryAndRevocation(t *testing.T) {
	service, store, _, now := fixture(t)
	ctx := context.Background()
	token, _, _ := service.NewToken(ctx)
	input := request(t, token)
	original, err := service.Enroll(ctx, input, "peer")
	if err != nil {
		t.Fatal(err)
	}
	connection := state(t, original)
	if _, err := service.Authenticate(ctx, connection); err != nil {
		t.Fatal(err)
	}
	early, err := service.Renew(ctx, connection, protocol.Renewal{CSR: input.CSR})
	if err != nil || early.Certificate != original.Certificate {
		t.Fatal("early renewal changed the certificate")
	}
	// Agents move to a new key at each renewal.
	rotated := request(t, token)
	if early, err := service.Renew(ctx, connection, protocol.Renewal{CSR: rotated.CSR}); err != nil || early.Certificate != original.Certificate {
		t.Fatal("early renewal with a new key changed the certificate")
	}
	*now = now.Add(24 * 24 * time.Hour)
	renewed, err := service.Renew(ctx, connection, protocol.Renewal{CSR: rotated.CSR})
	if err != nil || renewed.Certificate == original.Certificate || renewed.DeviceID != original.DeviceID {
		t.Fatalf("renewal failed: %v", err)
	}
	cert, _ := deviceidentity.ParseCertificate(renewed.Certificate)
	csr, _ := deviceidentity.ParseCSR(rotated.CSR)
	if cert == nil || string(cert.RawSubjectPublicKeyInfo) != string(csr.RawSubjectPublicKeyInfo) {
		t.Fatal("renewed certificate is not for the new key")
	}
	retry, err := service.Renew(ctx, connection, protocol.Renewal{CSR: rotated.CSR})
	if err != nil || retry.Certificate != renewed.Certificate {
		t.Fatal("lost-response retry was not idempotent")
	}
	// An agent that lost the reply retries an hour later.
	*now = now.Add(time.Hour)
	if again, err := service.Renew(ctx, connection, protocol.Renewal{CSR: rotated.CSR}); err != nil || again.Certificate != renewed.Certificate {
		t.Fatal("lost-response retry within the overlap failed")
	}
	*now = now.Add(time.Hour)
	if _, err := service.Authenticate(ctx, connection); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("superseded certificate survived overlap")
	}
	current := state(t, renewed)
	if _, err := service.Authenticate(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeDevice(ctx, renewed.DeviceID, *now); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, current); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device accepted on existing TLS state")
	}
	if _, err := service.Renew(ctx, current, protocol.Renewal{CSR: input.CSR}); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("revoked device renewed")
	}
	token, _, _ = service.NewToken(ctx)
	input = request(t, token)
	fresh, err := service.Enroll(ctx, input, "peer")
	if err != nil {
		t.Fatal(err)
	}
	expired := state(t, fresh)
	*now = now.Add(30 * 24 * time.Hour)
	if _, err := service.Authenticate(ctx, expired); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("expired certificate accepted on existing TLS state")
	}
	if _, err := service.Renew(ctx, expired, protocol.Renewal{CSR: input.CSR}); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("expired certificate renewed")
	}
}
func TestAuthorityPersistenceAndMissingOrWrongBackupFailsClosed(t *testing.T) {
	service, store, path, _ := fixture(t)
	ctx := context.Background()
	original := service.issuer.Certificate.Raw
	reopened, err := New(ctx, store, path)
	if err != nil || string(reopened.issuer.Certificate.Raw) != string(original) {
		t.Fatal("authority changed across restart")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, store, path); err == nil {
		t.Fatal("missing established authority silently recreated")
	}
	other, _, otherPath, _ := fixture(t)
	_ = other
	value, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, value, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, store, path); err == nil {
		t.Fatal("database accepted the wrong authority backup")
	}
}
func TestEnrollmentValidationAndThrottling(t *testing.T) {
	service, store, _, _ := fixture(t)
	ctx := context.Background()
	token, _, _ := service.NewToken(ctx)
	input := request(t, token)
	input.OS = "unsupported"
	if _, err := service.Enroll(ctx, input, "peer"); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("unsupported platform accepted")
	}
	input.OS = "windows"
	input.CSR = "invalid"
	for index := 0; index < 19; index++ {
		if _, err := service.Enroll(ctx, input, "peer"); !errors.Is(err, storage.ErrAuthentication) {
			t.Fatal("unexpected pre-limit error")
		}
	}
	if _, err := service.Enroll(ctx, input, "peer"); !errors.Is(err, ErrLimited) {
		t.Fatal("enrollment throttling absent")
	}
	// Other clients are not blocked by one client's attempts, and a valid
	// token still enrolls.
	for peer := 0; peer < 10; peer++ {
		for index := 0; index < 10; index++ {
			if _, err := service.Enroll(ctx, input, fmt.Sprintf("peer-%d", peer)); !errors.Is(err, storage.ErrAuthentication) {
				t.Fatal("unexpected limit for another client", err)
			}
		}
	}
	// A well-formed request with an unknown token is refused before any
	// certificate is signed.
	unknown := request(t, strings.Repeat("A", 43))
	if _, err := service.Enroll(ctx, unknown, "other"); !errors.Is(err, storage.ErrAuthentication) {
		t.Fatal("unknown token accepted", err)
	}
	if _, err := service.Enroll(ctx, request(t, token), "other"); err != nil {
		t.Fatal("valid enrollment refused", err)
	}
	list, err := store.Devices(ctx)
	if err != nil || len(list) != 1 {
		t.Fatal("only the valid enrollment may create a device")
	}
}
