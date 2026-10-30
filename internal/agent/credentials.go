package agent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devicekey"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// credentials is credentials.json in the SYSTEM-only state folder. Version 1
// kept the private key as plain PEM; version 2 refers to a protected key
// (in the TPM, or encrypted with DPAPI; see internal/devicekey).
type credentials struct {
	Version    int                 `json:"version"`
	DeviceURL  string              `json:"device_url"`
	ServerCA   string              `json:"server_ca"`
	PrivateKey string              `json:"private_key,omitempty"`
	Key        *devicekey.Ref      `json:"key,omitempty"`
	Credential protocol.Credential `json:"credential"`
}

// pendingKeyFile names a key that is not certified yet: one being enrolled,
// or the next key during a renewal. Retries reuse it.
const pendingKeyFile = "pending-key.json"

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read local credential or trust file")
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) > limit {
		return nil, errors.New("local credential or trust file is unreadable or too large")
	}
	return value, nil
}

// trust returns the explicit server trust bundle; an empty bundle (installers
// for servers with publicly trusted certificates) returns nil, so
// TLS uses the operating system's trusted roots.
func trust(value string) (*x509.CertPool, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(value)) {
		return nil, errors.New("invalid explicit server trust bundle")
	}
	return pool, nil
}
func requestJSON(ctx context.Context, c config.Agent, tlsConfig *tls.Config, origin, method, path string, input, output any) error {
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: proxyFunc(c.State)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return requestWithClient(ctx, client, origin, method, path, input, output)
}
func requestWithClient(ctx context.Context, client *http.Client, origin, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return errors.New("cannot encode device request")
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(origin, "/")+path, body)
	if err != nil {
		return errors.New("cannot construct device request")
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("device request failed; check connectivity, trusted CA, certificate validity, and enrollment state")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 201 {
		if response.StatusCode == 403 && response.Header.Get(protocol.DeviceStatusHeader) == "revoked" {
			return ErrDeviceRevoked
		}
		if response.StatusCode == 401 || response.StatusCode == 403 {
			return ErrDeviceRejected
		}
		if response.StatusCode == 429 {
			return ErrDeviceThrottled
		}
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return ErrRequestRejected
		}
		return errors.New("device endpoint returned an unsuccessful status")
	}
	limit := 32768
	if path == "/api/v1/agent/files/poll" {
		limit = 12 * 1024 * 1024
	}
	if path == "/api/v1/agent/scripts/poll" || path == "/api/v1/agent/evidence/poll" {
		// Scripts (and case scripts in evidence jobs) carry a
		// 64 KiB body that JSON escaping can expand several-fold.
		limit = 1024 * 1024
	}
	if path == "/api/v1/agent/terminal" {
		// Up to four 4 KiB inputs, which JSON escaping can expand several-fold.
		limit = 128 * 1024
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, int64(limit+1)))
	if err != nil || len(encoded) > limit {
		return errors.New("device response is unreadable or too large")
	}
	// Unknown reply fields are ignored so a newer server can add fields without
	// breaking deployed agents; every reply is still size-bounded and validated
	// by its caller. The server stays strict about what agents send.
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if decoder.Decode(output) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return errors.New("invalid device response")
	}
	return nil
}
func validateCredential(value protocol.Credential, key crypto.Signer, expectedID string) (tls.Certificate, error) {
	if !protocol.ValidID(value.DeviceID) || expectedID != "" && value.DeviceID != expectedID {
		return tls.Certificate{}, errors.New("server returned an unexpected device identity")
	}
	ca, err := deviceidentity.ParseCertificate(value.DeviceCA)
	if err != nil || !ca.IsCA {
		return tls.Certificate{}, errors.New("invalid device issuer certificate")
	}
	cert, err := deviceidentity.ParseCertificate(value.Certificate)
	if err != nil {
		return tls.Certificate{}, errors.New("invalid issued device certificate")
	}
	id, err := deviceidentity.DeviceID(cert)
	if err != nil || id != value.DeviceID {
		return tls.Certificate{}, errors.New("issued certificate identity mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return tls.Certificate{}, errors.New("device certificate is expired or has an invalid issuer")
	}
	public, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || !public.Equal(cert.PublicKey) {
		return tls.Certificate{}, errors.New("issued device certificate does not match the local private key")
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, nil
}
func saveInitial(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot exclusively create private agent state")
	}
	_, writeErr := file.Write(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist private agent state; retain this directory and use local recovery")
	}
	return nil
}
func (value credentials) save(directory string, replace bool) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("cannot encode private agent credentials")
	}
	path := filepath.Join(directory, "credentials.json")
	if !replace {
		return saveInitial(path, encoded)
	}
	file, err := os.CreateTemp(directory, ".credentials-*")
	if err != nil {
		return errors.New("cannot stage renewed agent credentials")
	}
	name := file.Name()
	defer os.Remove(name)
	_, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot persist renewed agent credentials")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("cannot replace renewed agent credentials; retry renewal before the old certificate expires")
	}
	return nil
}
func loadCredentials(directory string) (credentials, devicekey.Key, tls.Certificate, error) {
	encoded, err := readLimited(filepath.Join(directory, "credentials.json"), 32768)
	if err != nil {
		return credentials{}, nil, tls.Certificate{}, err
	}
	var value credentials
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) || !(value.Version == 1 && value.PrivateKey != "" && value.Key == nil || value.Version == 2 && value.PrivateKey == "" && value.Key != nil) {
		return credentials{}, nil, tls.Certificate{}, errors.New("invalid saved agent credentials")
	}
	// Reuse origin validation even when URLs come from persisted local state.
	if _, err := config.LoadAgent([]string{"-device-server", value.DeviceURL, "-server", value.DeviceURL}, func(string) string { return "" }); err != nil {
		return credentials{}, nil, tls.Certificate{}, errors.New("invalid saved device server origin")
	}
	var key devicekey.Key
	if value.Version == 1 {
		plain, e := deviceidentity.ParseKey([]byte(value.PrivateKey))
		if e != nil {
			return credentials{}, nil, tls.Certificate{}, errors.New("invalid saved private key")
		}
		key = devicekey.Unprotected(plain)
	} else if key, err = devicekey.Open(*value.Key); err != nil {
		return credentials{}, nil, tls.Certificate{}, err
	}
	pair, err := validateCredential(value.Credential, key, value.Credential.DeviceID)
	if err != nil {
		return credentials{}, nil, tls.Certificate{}, err
	}
	return value, key, pair, nil
}

// Enroll generates a key locally. Only its signed CSR leaves the device.
func Enroll(ctx context.Context, c config.Agent, token string) (string, error) {
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return "", errors.New("enrollment currently supports Windows x64")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", errors.New("cannot read device hostname")
	}
	return enroll(ctx, c, token, hostname, "windows", "amd64")
}
func enroll(ctx context.Context, c config.Agent, token, hostname, platform, architecture string) (string, error) {
	ca, err := readLimited(c.CAFile, 32768)
	if err != nil {
		return "", err
	}
	return enrollWith(ctx, c, token, ca, hostname, platform, architecture, false)
}

// enrollWith enrolls with the given trust bundle (empty: system trust). An
// installed service (reuseState) may enroll into the empty state folder that
// Windows Installer created; it never replaces saved credentials.
func enrollWith(ctx context.Context, c config.Agent, token string, ca []byte, hostname, platform, architecture string, reuseState bool) (string, error) {
	if len(token) != 43 || !protocol.ValidMetadata(hostname, platform, architecture) {
		return "", errors.New("invalid enrollment token or device metadata")
	}
	roots, err := trust(string(ca))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(c.State), 0700); err != nil {
		return "", errors.New("cannot create agent state parent")
	}
	if err := privatefs.CreateDirectory(c.State); err != nil {
		if !reuseState || !errors.Is(err, os.ErrExist) {
			return "", errors.New("agent state directory already exists or cannot be protected; use connect for an enrolled agent, or a new private state path for recovery")
		}
		if _, err := os.Stat(filepath.Join(c.State, "credentials.json")); err == nil {
			return "", errors.New("this device is already enrolled")
		}
		// Agents before version 2 credentials kept an interrupted attempt's
		// key in plain form; it was never certified.
		_ = os.Remove(filepath.Join(c.State, "pending-key.pem"))
		if err := privatefs.ProtectDirectory(c.State); err != nil {
			return "", errors.New("cannot protect the agent state directory")
		}
	}
	// The installed service keeps its key in the TPM where it can. Retries
	// reuse the key of an interrupted attempt.
	key, err := pendingKey(c.State, c.Service, nil)
	if err != nil {
		return "", err
	}
	csr, err := deviceidentity.CSR(key)
	if err != nil {
		return "", err
	}
	var credential protocol.Credential
	if err := requestJSON(ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, c.ServerURL, "POST", "/api/v1/enroll", protocol.Enrollment{Token: token, CSR: csr, Hostname: hostname, OS: platform, Architecture: architecture}, &credential); err != nil {
		return "", err
	}
	if _, err := validateCredential(credential, key, ""); err != nil {
		return "", err
	}
	ref := key.Ref()
	value := credentials{Version: 2, DeviceURL: c.DeviceURL, ServerCA: string(ca), Key: &ref, Credential: credential}
	if err := value.save(c.State, false); err != nil {
		return "", err
	}
	_ = os.Remove(filepath.Join(c.State, pendingKeyFile))
	return credential.DeviceID, nil
}

// pendingKey returns the key named in pending-key.json, or creates one and
// names it there first, so an interrupted request is retried with the same
// key. A pending key that is already the current one is replaced.
func pendingKey(state string, tpm bool, current *devicekey.Ref) (devicekey.Key, error) {
	path := filepath.Join(state, pendingKeyFile)
	if b, err := readLimited(path, 8192); err == nil {
		var ref devicekey.Ref
		if json.Unmarshal(b, &ref) == nil && (current == nil || !devicekey.Same(ref, *current)) {
			if key, err := devicekey.Open(ref); err == nil {
				return key, nil
			}
		}
		_ = os.Remove(path)
	}
	key, err := devicekey.New(tpm)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(key.Ref())
	if err == nil {
		err = saveInitial(path, b)
	}
	if err != nil {
		_ = key.Delete()
		return nil, errors.New("cannot record the new device key")
	}
	return key, nil
}

// Connect checks the saved identity once; Run schedules heartbeats.
func Connect(ctx context.Context, c config.Agent) (string, error) {
	value, _, pair, err := loadCredentials(c.State)
	if err != nil {
		return "", err
	}
	roots, err := trust(value.ServerCA)
	if err != nil {
		return "", err
	}
	var result protocol.Identity
	if err := requestJSON(ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}, value.DeviceURL, "GET", "/api/v1/agent/identity", nil, &result); err != nil {
		return "", err
	}
	if result.DeviceID != value.Credential.DeviceID {
		return "", errors.New("authenticated server returned a different device identity")
	}
	return result.DeviceID, nil
}
func Renew(ctx context.Context, c config.Agent) (string, error) {
	value, key, pair, err := loadCredentials(c.State)
	if err != nil {
		return "", err
	}
	roots, err := trust(value.ServerCA)
	if err != nil {
		return "", err
	}
	request := func(k devicekey.Key) (protocol.Credential, error) {
		var result protocol.Credential
		csr, err := deviceidentity.CSR(k)
		if err == nil {
			err = requestJSON(ctx, c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}, value.DeviceURL, "POST", "/api/v1/agent/renew", protocol.Renewal{CSR: csr}, &result)
		}
		if err == nil && result.DeviceCA != value.Credential.DeviceCA {
			err = errors.New("renewal attempted to replace the trusted device issuer")
		}
		return result, err
	}
	// Each renewal moves to a new key (version 2 credentials only, so an
	// agent rolled back to a release without them still reads the file).
	next := key
	if value.Version == 2 {
		if next, err = pendingKey(c.State, c.Service, value.Key); err != nil {
			return "", err
		}
	}
	result, err := request(next)
	if err != nil && next != key && (errors.Is(err, ErrDeviceRejected) || errors.Is(err, ErrRequestRejected)) {
		// Servers before 0.1.4 renew only the key already in use.
		next = key
		result, err = request(key)
	}
	if err != nil {
		return "", err
	}
	// A certificate for the current key (an older server, or one that is not
	// due yet) keeps the current key; the pending one is used next time.
	adopted := next
	if _, err := validateCredential(result, next, value.Credential.DeviceID); err != nil {
		if _, err := validateCredential(result, key, value.Credential.DeviceID); err != nil {
			return "", err
		}
		adopted = key
	}
	value.Credential = result
	if adopted != key {
		ref := adopted.Ref()
		value.Key = &ref
	}
	if err := value.save(c.State, true); err != nil {
		return "", err
	}
	if adopted != key {
		_ = os.Remove(filepath.Join(c.State, pendingKeyFile))
		// A TPM key left behind if this fails holds no certificate.
		_ = key.Delete()
	}
	return result.DeviceID, nil
}

// protectCredentials moves version 1 credentials (a plain key) to version 2:
// the same key, encrypted with DPAPI. The next renewal moves to a new key,
// in the TPM for the installed service.
func protectCredentials(state string) (bool, error) {
	value, _, _, err := loadCredentials(state)
	if err != nil || value.Version != 1 || runtime.GOOS != "windows" {
		return false, err
	}
	plain, err := deviceidentity.ParseKey([]byte(value.PrivateKey))
	if err != nil {
		return false, err
	}
	key, err := devicekey.Protect(plain)
	if err != nil {
		return false, err
	}
	ref := key.Ref()
	value.Version, value.PrivateKey, value.Key = 2, "", &ref
	return true, value.save(state, true)
}
