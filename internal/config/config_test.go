package config

import (
	"errors"
	"flag"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func emptyEnv(string) string { return "" }

func TestDesktopIsOnInTheInstalledServiceOnly(t *testing.T) {
	c, e := LoadAgent(nil, emptyEnv)
	if e != nil || c.Desktop {
		t.Fatal("console mode has no desktop companion pipe")
	}
	if _, e = LoadAgent([]string{"-desktop=bad"}, emptyEnv); e == nil {
		t.Fatal("invalid desktop mode accepted")
	}
	args := []string{"-service", "-state", filepath.Join(t.TempDir(), "state"), "-log-directory", filepath.Join(t.TempDir(), "logs")}
	c, e = LoadAgent(args, emptyEnv)
	if e != nil || !c.Desktop || !c.Inventory || !c.Processes || !c.Terminal || !c.Files || !c.Scripts {
		t.Fatal("service features default on", e)
	}
	c, e = LoadAgent(append(args, "-desktop=false"), emptyEnv)
	if e != nil || c.Desktop || !c.Processes {
		t.Fatal("desktop not independently disabled", e)
	}
}

func TestFilesConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, emptyEnv)
	if e != nil || !c.Files {
		t.Fatal("files should default on")
	}
	c, e = LoadAgent([]string{"-files=false"}, emptyEnv)
	if e != nil || c.Files || !c.Scripts {
		t.Fatal("files not independently disabled")
	}
	if _, e = LoadAgent([]string{"-files=bad"}, emptyEnv); e == nil {
		t.Fatal("invalid files setting accepted")
	}
}

func TestSoftwareConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, emptyEnv)
	if e != nil || !c.Software {
		t.Fatal("software should default on")
	}
	c, e = LoadAgent([]string{"-software=false"}, emptyEnv)
	if e != nil || c.Software || !c.Inventory || !c.Uptime || !c.WindowsUpdates {
		t.Fatal("software not independently disabled")
	}
	c, e = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_SOFTWARE" {
			return "false"
		}
		return ""
	})
	if e != nil || c.Software {
		t.Fatal("software environment ignored")
	}
	if _, e = LoadAgent([]string{"-software=bad"}, emptyEnv); e == nil {
		t.Fatal("invalid software flag accepted")
	}
}

func TestProcessesConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, emptyEnv)
	if e != nil || !c.Processes {
		t.Fatal("processes should default on")
	}
	c, e = LoadAgent([]string{"-processes=false"}, emptyEnv)
	if e != nil || c.Processes || !c.Inventory || !c.Uptime || !c.WindowsUpdates {
		t.Fatal("processes not independently disabled")
	}
	c, e = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_PROCESSES" {
			return "false"
		}
		return ""
	})
	if e != nil || c.Processes {
		t.Fatal("processes environment ignored")
	}
	if _, e = LoadAgent([]string{"-processes=bad"}, emptyEnv); e == nil {
		t.Fatal("invalid processes flag accepted")
	}
}

func TestUptimeConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || !c.Uptime {
		t.Fatal("uptime should default on")
	}
	c, err = LoadAgent([]string{"-uptime=false"}, emptyEnv)
	if err != nil || c.Uptime || !c.Inventory || !c.DiskSpace || !c.Memory || !c.CPU {
		t.Fatal("uptime cannot be disabled independently")
	}
	c, err = LoadAgent([]string{"-cpu=false"}, emptyEnv)
	if err != nil || !c.Uptime {
		t.Fatal("CPU changed uptime reporting")
	}
	if _, err := LoadAgent([]string{"-uptime=invalid"}, emptyEnv); err == nil {
		t.Fatal("invalid uptime flag accepted")
	}
	c, err = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_UPTIME" {
			return "false"
		}
		return ""
	})
	if err != nil || c.Uptime {
		t.Fatal("uptime environment ignored")
	}
}

func TestCPUConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || !c.CPU {
		t.Fatal("CPU should default on")
	}
	c, err = LoadAgent([]string{"-cpu=false"}, emptyEnv)
	if err != nil || c.CPU || !c.Inventory || !c.DiskSpace || !c.Memory {
		t.Fatal("CPU cannot be disabled independently")
	}
	c, err = LoadAgent([]string{"-memory=false"}, emptyEnv)
	if err != nil || !c.CPU {
		t.Fatal("RAM changed CPU reporting")
	}
	if _, err := LoadAgent([]string{"-cpu=invalid"}, emptyEnv); err == nil {
		t.Fatal("invalid CPU flag accepted")
	}
	c, err = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_CPU" {
			return "false"
		}
		return ""
	})
	if err != nil || c.CPU {
		t.Fatal("CPU environment override ignored")
	}
}

func TestMemoryConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || !c.Memory {
		t.Fatal("memory should default on")
	}
	c, err = LoadAgent([]string{"-memory=false"}, emptyEnv)
	if err != nil || c.Memory || !c.Inventory || !c.DiskSpace {
		t.Fatal("memory cannot be disabled independently")
	}
	c, err = LoadAgent([]string{"-inventory=false", "-disk-space=false"}, emptyEnv)
	if err != nil || !c.Memory {
		t.Fatal("other settings changed memory reporting")
	}
	if _, err := LoadAgent([]string{"-memory=invalid"}, emptyEnv); err == nil {
		t.Fatal("invalid memory flag accepted")
	}
	c, err = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_MEMORY" {
			return "false"
		}
		return ""
	})
	if err != nil || c.Memory {
		t.Fatal("memory environment override ignored")
	}
}

func TestDiskSpaceConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || !c.DiskSpace {
		t.Fatal("disk space should default on")
	}
	c, err = LoadAgent([]string{"-disk-space=false"}, emptyEnv)
	if err != nil || c.DiskSpace || !c.Inventory {
		t.Fatal("disk cannot be disabled independently")
	}
	c, err = LoadAgent([]string{"-inventory=false"}, emptyEnv)
	if err != nil || !c.DiskSpace || c.Inventory {
		t.Fatal("inventory changed disk reporting")
	}
	if _, err := LoadAgent([]string{"-disk-space=invalid"}, emptyEnv); err == nil {
		t.Fatal("invalid disk flag accepted")
	}
	c, err = LoadAgent(nil, func(key string) string {
		if key == "OPENRMM_AGENT_DISK_SPACE" {
			return "false"
		}
		return ""
	})
	if err != nil || c.DiskSpace {
		t.Fatal("disk environment override ignored")
	}
}

func TestInventoryConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || !c.Inventory || c.InventoryInterval != 15*time.Minute {
		t.Fatal("wrong inventory defaults")
	}
	c, err = LoadAgent([]string{"-inventory=false"}, emptyEnv)
	if err != nil || c.Inventory {
		t.Fatal("inventory cannot be disabled independently")
	}
	for _, args := range [][]string{{"-inventory=invalid"}, {"-inventory-interval=1s"}, {"-inventory-interval=16m"}} {
		if _, err := LoadAgent(args, emptyEnv); err == nil {
			t.Fatal("invalid inventory configuration accepted")
		}
	}
}

func TestServicePathsAndExclusiveMode(t *testing.T) {
	dir := t.TempDir()
	valid := []string{"-service", "-state", filepath.Join(dir, "state"), "-log-directory", filepath.Join(dir, "logs")}
	if _, err := LoadAgent(valid, emptyEnv); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-service"},
		{"-service", "-state", "relative", "-log-directory", dir},
		{"-service", "-state", dir, "-log-directory", dir},
		{"-log-directory", dir},
		append(append([]string{}, valid...), "-run"),
		append(append([]string{}, valid...), "-enroll"),
	} {
		if _, err := LoadAgent(args, emptyEnv); err == nil {
			t.Fatal("invalid service configuration accepted")
		}
	}
}

func TestServerConfiguration(t *testing.T) {
	c, err := LoadServer(nil, emptyEnv)
	if err != nil || c.Listen != "127.0.0.1:8443" {
		t.Fatalf("unexpected defaults: %+v, %v", c, err)
	}
	c, err = LoadServer([]string{"-listen", "[::1]:9443"}, func(key string) string {
		if key == "OPENRMM_SERVER_LISTEN" {
			return "127.0.0.1:9444"
		}
		return ""
	})
	if err != nil || c.Listen != "[::1]:9443" {
		t.Fatalf("flags must override environment: %+v, %v", c, err)
	}
	for _, address := range []string{":8443", "0.0.0.0:8443", "[::]:8443", "192.168.1.2:8443", "localhost:8443", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "[::1%zone]:8443"} {
		t.Run(address, func(t *testing.T) {
			if _, err := LoadServer([]string{"-listen", address}, emptyEnv); err == nil {
				t.Fatal("unsafe or invalid listener accepted")
			}
		})
	}
}

func TestAgentConfiguration(t *testing.T) {
	c, err := LoadAgent(nil, emptyEnv)
	if err != nil || c.ServerURL != "https://127.0.0.1:8443" || c.Timeout != 5*time.Second {
		t.Fatalf("unexpected defaults: %+v, %v", c, err)
	}
	for _, origin := range []string{"http://127.0.0.1:8443", "https://user:password@localhost", "https://localhost?token=secret", "https://localhost?", "https://localhost/#secret", "https://localhost/api", "https://localhost:0", "https://localhost:99999", "https:///healthz", "//localhost"} {
		t.Run(origin, func(t *testing.T) {
			if _, err := LoadAgent([]string{"-server", origin}, emptyEnv); err == nil {
				t.Fatal("unsafe or invalid server origin accepted")
			}
		})
	}
	for _, timeout := range []string{"0s", "-1s", "100ms", "2m", "invalid"} {
		if _, err := LoadAgent([]string{"-timeout", timeout}, emptyEnv); err == nil {
			t.Fatalf("invalid timeout accepted: %s", timeout)
		}
	}
}

func TestContainerBindingRequiresExplicitOptIn(t *testing.T) {
	c, err := LoadServer([]string{"-listen", "0.0.0.0:8443", "-container-network=true"}, emptyEnv)
	if err != nil || !c.ContainerNetwork {
		t.Fatalf("explicit container listener failed: %v", err)
	}
	for _, address := range []string{"192.168.1.2:8443", "localhost:8443"} {
		if _, err := LoadServer([]string{"-listen", address, "-container-network=true"}, emptyEnv); err == nil {
			t.Fatal("container mode should allow only loopback or wildcard IPs")
		}
	}
	if _, err := LoadServer([]string{"-container-network=invalid"}, emptyEnv); err == nil {
		t.Fatal("invalid container mode accepted")
	}
}

func TestConfigurationErrorsDoNotEchoInput(t *testing.T) {
	const secret = "sensitive-test-value"
	for _, load := range []func([]string, Env) error{
		func(args []string, env Env) error { _, err := LoadServer(args, env); return err },
		func(args []string, env Env) error { _, err := LoadAgent(args, env); return err },
	} {
		for _, args := range [][]string{{"-unknown=" + secret}, {"-log-level", secret}, {secret}} {
			err := load(args, emptyEnv)
			if err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("error was absent or exposed input: %v", err)
			}
		}
		if err := load([]string{"-help"}, emptyEnv); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("help should be distinguishable: %v", err)
		}
	}
}

func TestDeviceConfigurationBoundaries(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8444", "192.168.1.2:8444", "localhost:8444", "127.0.0.1:0", "127.0.0.1:8443"} {
		if _, err := LoadServer([]string{"-device-listen", address}, emptyEnv); err == nil {
			t.Fatal("invalid or unapproved device listener accepted")
		}
	}
	if _, err := LoadServer([]string{"-device-listen", "0.0.0.0:8444", "-container-network=true"}, emptyEnv); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://localhost:8444", "https://user:secret@localhost", "https://localhost?token=secret", "https://localhost/devices", "https://localhost:0"} {
		if _, err := LoadAgent([]string{"-device-server", origin}, emptyEnv); err == nil {
			t.Fatal("invalid device origin accepted")
		}
	}
	for _, arguments := range [][]string{{"-enroll", "-connect"}, {"-connect", "-renew"}, {"-enroll", "-ready"}, {"-state", " "}} {
		if _, err := LoadAgent(arguments, emptyEnv); err == nil {
			t.Fatal("invalid agent operation accepted")
		}
	}
}

func TestHeartbeatTimingConfiguration(t *testing.T) {
	server, err := LoadServer(nil, emptyEnv)
	if err != nil || server.OfflineAfter != 120*time.Second {
		t.Fatal("incorrect offline default")
	}
	agent, err := LoadAgent([]string{"-run"}, emptyEnv)
	if err != nil || !agent.Run || agent.HeartbeatInterval != 30*time.Second {
		t.Fatal("incorrect heartbeat defaults")
	}
	for _, duration := range []string{"0s", "2s", "25h", "invalid"} {
		if _, err := LoadServer([]string{"-offline-after", duration}, emptyEnv); err == nil {
			t.Fatal("invalid offline threshold accepted")
		}
	}
	for _, duration := range []string{"0s", "100ms", "6m", "invalid"} {
		if _, err := LoadAgent([]string{"-heartbeat-interval", duration}, emptyEnv); err == nil {
			t.Fatal("invalid heartbeat interval accepted")
		}
	}
	if _, err := LoadAgent([]string{"-run", "-enroll"}, emptyEnv); err == nil {
		t.Fatal("conflicting agent modes accepted")
	}
}

func TestServicesIndependentConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, func(string) string { return "" })
	if e != nil || !c.Services {
		t.Fatal("services default missing", e)
	}
	c, e = LoadAgent([]string{"-services=false"}, func(string) string { return "" })
	if e != nil || c.Services || !c.Inventory || !c.DiskSpace || !c.Memory || !c.CPU || !c.Uptime {
		t.Fatal("services disable affected other workers", e)
	}
	c, e = LoadAgent(nil, func(k string) string {
		if k == "OPENRMM_AGENT_SERVICES" {
			return "false"
		}
		return ""
	})
	if e != nil || c.Services {
		t.Fatal("services environment ignored")
	}
	if _, e = LoadAgent([]string{"-services=maybe"}, func(string) string { return "" }); e == nil {
		t.Fatal("invalid services setting accepted")
	}
}

func TestWindowsUpdatesIndependentConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, func(string) string { return "" })
	if e != nil || !c.WindowsUpdates {
		t.Fatal("default updates flag", e)
	}
	c, e = LoadAgent([]string{"-windows-updates=false"}, func(string) string { return "" })
	if e != nil || c.WindowsUpdates || !c.EventLogs || !c.Services || !c.Inventory {
		t.Fatal("updates isolation", e)
	}
	if _, e = LoadAgent([]string{"-windows-updates=nope"}, func(string) string { return "" }); e == nil {
		t.Fatal("invalid updates flag accepted")
	}
}
func TestEventLogsIndependentConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, func(string) string { return "" })
	if e != nil || !c.EventLogs {
		t.Fatal("event log default missing", e)
	}
	c, e = LoadAgent([]string{"-event-logs=false"}, func(string) string { return "" })
	if e != nil || c.EventLogs || !c.Services || !c.Uptime || !c.CPU || !c.Memory || !c.DiskSpace || !c.Inventory {
		t.Fatal("event logs disable affected other collectors", e)
	}
	if _, e = LoadAgent([]string{"-event-logs=invalid"}, func(string) string { return "" }); e == nil {
		t.Fatal("invalid event logs option accepted")
	}
}

func TestScriptsConfiguration(t *testing.T) {
	c, e := LoadAgent(nil, emptyEnv)
	if e != nil || !c.Scripts || !c.Terminal {
		t.Fatal("scripts and terminal default on")
	}
	c, e = LoadAgent([]string{"-scripts=false"}, emptyEnv)
	if e != nil || c.Scripts || !c.Processes || !c.Software || !c.WindowsUpdates {
		t.Fatal("script flag independence")
	}
	c, e = LoadAgent(nil, func(k string) string {
		if k == "OPENRMM_AGENT_SCRIPTS" {
			return "false"
		}
		return ""
	})
	if e != nil || c.Scripts {
		t.Fatal("script env")
	}
	if _, e = LoadAgent([]string{"-scripts=bad"}, emptyEnv); e == nil {
		t.Fatal("invalid setting")
	}
}

func TestAgentOriginsAreNormalized(t *testing.T) {
	c, e := LoadAgent([]string{"-server", "https://rmm.example.test:8443/", "-device-server", "https://rmm.example.test:8444/"}, emptyEnv)
	if e != nil || c.ServerURL != "https://rmm.example.test:8443" || c.DeviceURL != "https://rmm.example.test:8444" {
		t.Fatal("trailing slash kept", c.ServerURL, c.DeviceURL, e)
	}
	if _, e = LoadAgent([]string{"-device-server", "https://rmm.example.test:8444/api"}, emptyEnv); e == nil {
		t.Fatal("device URL path accepted")
	}
}

// An ACME domain replaces the certificate files; the domain,
// directory and email are checked; the cache defaults next to the database.
func TestACMEConfiguration(t *testing.T) {
	c, err := LoadServer([]string{"-acme-domain", "RMM.Example.com.", "-tls-cert", "", "-tls-key", "", "-database", filepath.Join("data", "db")}, emptyEnv)
	if err != nil || c.ACMEDomain != "rmm.example.com" || c.ACMECache != filepath.Join("data", "acme") {
		t.Fatal(c.ACMEDomain, c.ACMECache, err)
	}
	for _, args := range [][]string{
		{"-acme-domain", "*.example.com"},
		{"-acme-domain", "192.0.2.1"},
		{"-acme-domain", "localhost"},
		{"-acme-domain", "rmm.example.com", "-acme-directory", "http://ca.example/dir"},
		{"-acme-domain", "rmm.example.com", "-acme-email", "not an email"},
		{"-tls-cert", ""},
	} {
		if _, err := LoadServer(args, emptyEnv); err == nil {
			t.Fatal("accepted", args)
		}
	}
}

// A LAN install names the server's hosts; agents then trust the
// server's own CA, and the install command's addresses are validated.
func TestServerHostsConfiguration(t *testing.T) {
	c, err := LoadServer([]string{"-server-hosts", " RMM.lan,192.168.1.20 , rmm.lan", "-tls-cert", "", "-tls-key", "", "-encryption-key", filepath.Join("secrets", "key.bin"),
		"-public-url", "https://192.168.1.20/", "-public-device-url", "https://192.168.1.20:8444"}, emptyEnv)
	if err != nil || len(c.ServerHosts) != 2 || c.ServerCADir != filepath.Join("secrets", "server-ca") || c.CAFile != filepath.Join("secrets", "server-ca", "ca.pem") ||
		c.PublicURL != "https://192.168.1.20" || c.PublicDeviceURL != "https://192.168.1.20:8444" {
		t.Fatal(c, err)
	}
	for _, args := range [][]string{
		{"-server-hosts", "rmm.lan", "-acme-domain", "rmm.example.com"},
		{"-server-hosts", "bad host"},
		{"-server-hosts", "0.0.0.0"},
		{"-public-url", "https://rmm.lan"},
		{"-public-url", "https://rmm.lan", "-public-device-url", "https://rmm.lan"},
		{"-public-url", "http://rmm.lan", "-public-device-url", "https://rmm.lan:8444"},
	} {
		if _, err := LoadServer(args, emptyEnv); err == nil {
			t.Fatal("accepted", args)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := LoadServer([]string{"-trusted-proxies", " 10.0.0.0/8, 192.0.2.7,::ffff:198.51.100.1, fd00::1/64"}, emptyEnv)
	if err != nil || len(c.TrustedProxies) != 4 || c.TrustedProxies[1].String() != "192.0.2.7/32" || c.TrustedProxies[2].String() != "198.51.100.1/32" || c.TrustedProxies[3].String() != "fd00::/64" {
		t.Fatal(c.TrustedProxies, err)
	}
	if c, err := LoadServer(nil, emptyEnv); err != nil || c.TrustedProxies != nil {
		t.Fatal("proxies trusted by default")
	}
	for _, v := range []string{"proxy.lan", "10.0.0.0/33", "fe80::1%eth0", strings.Repeat("10.0.0.1,", 21)} {
		if _, err := LoadServer([]string{"-trusted-proxies", v}, emptyEnv); err == nil {
			t.Fatal("accepted", v)
		}
	}
}
