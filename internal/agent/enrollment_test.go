package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/cpu"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/deviceidentity"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/diskspace"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/inventory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/memory"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/server"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/uptime"
)

func TestEnrollmentSavedIdentityRenewalAndTLSIsolation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := storage.Open(ctx, filepath.Join(root, "data", "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := devices.New(ctx, store, filepath.Join(root, "secrets", "ca", "authority.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tlsPath := filepath.Join(root, "tls")
	if err := devtls.Generate(tlsPath); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(tlsPath, "server.pem"), filepath.Join(tlsPath, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewUnstartedServer(server.Handler(store, nil, service))
	admin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	admin.StartTLS()
	defer admin.Close()
	device := httptest.NewUnstartedServer(server.DeviceHandler(service))
	device.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: service.Roots()}
	device.StartTLS()
	defer device.Close()
	c := config.Agent{ServerURL: admin.URL, DeviceURL: device.URL, CAFile: filepath.Join(tlsPath, "ca.pem"), State: filepath.Join(root, "agent"), Timeout: 5 * time.Second}
	token, _, err := service.NewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := enroll(ctx, c, token, "Windows integration test", "windows", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := Connect(ctx, c); err != nil || actual != id {
		t.Fatalf("saved identity not usable: %v", err)
	}
	if _, err := enroll(ctx, c, token, "test", "windows", "amd64"); err == nil {
		t.Fatal("existing credential directory overwritten")
	}
	encoded, err := os.ReadFile(filepath.Join(c.State, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), token) {
		t.Fatal("enrollment token retained in agent credentials")
	}
	if _, err := os.Stat(filepath.Join(c.State, "pending-key.pem")); !os.IsNotExist(err) {
		t.Fatal("pending key not cleaned after successful persistence")
	}
	if actual, err := Renew(ctx, c); err != nil || actual != id {
		t.Fatalf("safe early renewal check failed: %v", err)
	}
	value, _, clientPair, err := loadCredentials(c.State)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust(value.ServerCA)
	if err != nil {
		t.Fatal(err)
	}
	unauthTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer unauthTransport.CloseIdleConnections()
	client := &http.Client{Transport: unauthTransport, Timeout: time.Second}
	if response, err := client.Get(device.URL + "/api/v1/agent/identity"); err == nil {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		t.Fatal("device listener accepted a missing client certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientPair}}}
	defer transport.CloseIdleConnections()
	client = &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(device.URL + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("administrator route present on agent listener")
	}
	response, err = client.Get(admin.URL + "/api/v1/agent/identity")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("device route present on administrator listener")
	}
	heartbeat, err := newHeartbeatSession(c, protocol.Heartbeat{Hostname: "heartbeat test", OS: "windows", Architecture: "amd64", AgentVersion: Version})
	if err != nil {
		t.Fatal(err)
	}
	defer heartbeat.close()
	if err := heartbeat.pulse(ctx); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(protocol.Inventory{Hostname: "<script>untrusted</script>", OS: "windows", OSVersion: "10.0", OSBuild: 19045, Architecture: "amd64", AgentVersion: Version})
	feature := protocol.FeatureReport{Capability: inventory.Capability, Status: "ok", Data: data}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", feature); err != nil {
		t.Fatal(err)
	}
	gotInventory, err := store.Inventory(ctx, id)
	if err != nil || gotInventory.Data == nil || gotInventory.Data.OSBuild != 19045 {
		t.Fatal("authenticated inventory not recorded")
	}
	for _, extra := range []string{`"device_id":"ffffffffffffffffffffffffffffffff"`, `"received_at":9999999999`} {
		body := `{"capability":{"name":"inventory","version":1},"status":"disabled",` + extra + `}`
		response, err := client.Post(device.URL+"/api/v1/agent/features", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("feature report accepted a claimed identity/time")
		}
	}
	feature.Data = json.RawMessage(`{"hostname":"test","os":"windows","os_version":"10.0","os_build":19045,"architecture":"amd64","agent_version":"test","username":"forbidden"}`)
	if err := heartbeat.send(ctx, "/api/v1/agent/features", feature); !errors.Is(err, ErrRequestRejected) {
		t.Fatal("inventory accepted forbidden fields")
	}
	feature.Status, feature.Data = "failed", nil
	if err := heartbeat.send(ctx, "/api/v1/agent/features", feature); err != nil {
		t.Fatal(err)
	}
	if err := heartbeat.pulse(ctx); err != nil {
		t.Fatal("failed inventory blocked heartbeat")
	}
	list, err := store.Devices(ctx)
	if err != nil || len(list) != 1 || list[0].LastContactAt == nil {
		t.Fatal("authenticated heartbeat not recorded")
	}
	for _, extra := range []string{`"received_at":9999999999`, `"device_id":"ffffffffffffffffffffffffffffffff"`} {
		body := `{"hostname":"test","os":"windows","architecture":"amd64","agent_version":"test",` + extra + `}`
		response, err := client.Post(device.URL+"/api/v1/agent/heartbeat", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("heartbeat accepted a client timestamp or claimed device ID")
		}
	}
	// Keep the same mTLS transport/connection across revocation.
	uptimeReport := protocol.FeatureReport{Capability: uptime.Capability, Status: "ok", Data: json.RawMessage(`{"uptime_seconds":3600,"estimated_boot_at":1800000000}`)}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", uptimeReport); err != nil {
		t.Fatal(err)
	}
	gotUptime, err := store.Uptime(ctx, id)
	if err != nil || gotUptime.Data == nil || gotUptime.Data.UptimeSeconds != 3600 {
		t.Fatal("authenticated uptime not stored")
	}
	badUptime := uptimeReport
	badUptime.Data = json.RawMessage(`{"uptime_seconds":3600,"estimated_boot_at":1800000000,"received_at":9999999999}`)
	if err := heartbeat.send(ctx, "/api/v1/agent/features", badUptime); !errors.Is(err, ErrRequestRejected) {
		t.Fatal("uptime accepted a claimed receipt timestamp")
	}
	cpuReport := protocol.FeatureReport{Capability: cpu.Capability, Status: "ok", Data: json.RawMessage(`{"usage_percent":75,"sample_ms":1000}`)}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", cpuReport); err != nil {
		t.Fatal(err)
	}
	gotCPU, err := store.CPU(ctx, id)
	if err != nil || gotCPU.Data == nil || gotCPU.Data.UsagePercent != 75 {
		t.Fatal("authenticated CPU not stored")
	}
	badCPU := cpuReport
	badCPU.Data = json.RawMessage(`{"usage_percent":101,"sample_ms":1000}`)
	if err := heartbeat.send(ctx, "/api/v1/agent/features", badCPU); !errors.Is(err, ErrRequestRejected) {
		t.Fatal("invalid CPU accepted")
	}
	memoryReport := protocol.FeatureReport{Capability: memory.Capability, Status: "ok", Data: json.RawMessage(`{"total_bytes":100,"available_bytes":25}`)}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", memoryReport); err != nil {
		t.Fatal(err)
	}
	gotMemory, err := store.Memory(ctx, id)
	if err != nil || gotMemory.Data == nil || gotMemory.Data.AvailableBytes != 25 {
		t.Fatal("authenticated RAM not recorded")
	}
	badMemory := memoryReport
	badMemory.Data = json.RawMessage(`{"total_bytes":100,"available_bytes":25,"processes":[]}`)
	if err := heartbeat.send(ctx, "/api/v1/agent/features", badMemory); !errors.Is(err, ErrRequestRejected) {
		t.Fatal("memory accepted forbidden fields")
	}
	diskReport := protocol.FeatureReport{Capability: diskspace.Capability, Status: "ok", Data: json.RawMessage(`{"drive":"C:\\","total_bytes":100,"available_bytes":25}`)}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", diskReport); err != nil {
		t.Fatal(err)
	}
	gotDisk, err := store.DiskSpace(ctx, id)
	if err != nil || gotDisk.Data == nil || gotDisk.Data.AvailableBytes != 25 {
		t.Fatal("authenticated disk reading not recorded")
	}
	badDisk := diskReport
	badDisk.Data = json.RawMessage(`{"drive":"C:\\","total_bytes":100,"available_bytes":101}`)
	if err := heartbeat.send(ctx, "/api/v1/agent/features", badDisk); !errors.Is(err, ErrRequestRejected) {
		t.Fatal("invalid disk bytes accepted")
	}
	for _, extra := range []string{`"device_id":"ffffffffffffffffffffffffffffffff"`, `"received_at":9999999999`} {
		body := `{"capability":{"name":"disk_space","version":1},"status":"disabled",` + extra + `}`
		response, err := client.Post(device.URL+"/api/v1/agent/features", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("disk report accepted claimed identity/time")
		}
	}
	response, err = client.Get(device.URL + "/api/v1/agent/identity")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("identity probe failed")
	}
	if err := store.RevokeDevice(ctx, id, time.Now()); err != nil {
		t.Fatal(err)
	}
	reused := false
	deniedRequest, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}), http.MethodGet, device.URL+"/api/v1/agent/identity", nil)
	response, err = client.Do(deniedRequest)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if !reused {
		t.Fatal("revocation check did not reuse the existing TLS connection")
	}
	if response.StatusCode != 403 || response.Header.Get(protocol.DeviceStatusHeader) != "revoked" {
		t.Fatal("revocation did not block subsequent request with an explicit marker")
	}
	if err := heartbeat.pulse(ctx); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked heartbeat not recognised as revocation")
	}
	// While revoked, other requests stay local: nothing else reaches the server.
	if err := heartbeat.send(ctx, "/api/v1/agent/features", feature); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked feature report accepted")
	}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", diskReport); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked disk report accepted")
	}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", memoryReport); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked memory report accepted")
	}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", cpuReport); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked CPU accepted")
	}
	if err := heartbeat.send(ctx, "/api/v1/agent/features", uptimeReport); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("revoked uptime accepted")
	}
	if _, err := Connect(ctx, c); err == nil {
		t.Fatal("revoked saved identity remained usable")
	}
	if _, err := Renew(ctx, c); err == nil {
		t.Fatal("revoked saved identity renewed")
	}
	// A trusted HTTPS peer cannot substitute a different identity or private key.
	key, err := deviceidentity.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCredential(protocol.Credential{DeviceID: "ffffffffffffffffffffffffffffffff", Certificate: value.Credential.Certificate, DeviceCA: value.Credential.DeviceCA}, key, ""); err == nil {
		t.Fatal("mismatched issued identity accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := heartbeat.pulse(ctx); err == nil || errors.Is(err, ErrDeviceRejected) || errors.Is(err, ErrDeviceRevoked) {
		t.Fatal("storage outage was misreported as revoked credentials")
	}
}
