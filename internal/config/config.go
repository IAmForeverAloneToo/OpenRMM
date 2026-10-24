// Package config loads process configuration without logging user-supplied values.
package config

import (
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/lancert"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type Server struct {
	Listen           string
	CertFile         string
	KeyFile          string
	CAFile           string
	LogLevel         slog.Level
	Database         string
	ContainerNetwork bool
	StorageInfo      bool
	EncryptionKey    string
	AdminSetup       bool
	AdminConfirm     bool
	AdminReset       bool
	// AdminLink prints a one-time first-administrator setup link token.
	AdminLink bool
	// Health probes the running server's readiness over loopback (container
	// health checks) and exits.
	Health          bool
	DeviceListen    string
	DeviceAuthority string
	OfflineAfter    time.Duration
	AlertSMTPConfig string
	EvidenceDir     string
	EvidenceQuota   int64
	// With an ACME domain the dashboard certificate comes from an
	// ACME CA (Let's Encrypt by default) instead of the certificate files.
	ACMEDomain    string
	ACMEEmail     string
	ACMEDirectory string
	ACMECache     string
	// Without a public domain the server keeps its own CA in
	// ServerCADir and issues its certificate for ServerHosts.
	ServerHosts []string
	ServerCADir string
	// PublicURL and PublicDeviceURL fill empty installer settings at start.
	PublicURL       string
	PublicDeviceURL string
	// The folder shared with the updater sidecar (empty without
	// one) and operator release keys trusted next to the project key.
	UpdaterDir  string
	ReleaseKeys []string
}

type Agent struct {
	ServerURL string
	CAFile    string
	Timeout   time.Duration
	LogLevel  slog.Level
	Ready     bool
	Enroll    bool
	Connect   bool
	Renew     bool
	// ReleaseIsolation is a release code: lift network isolation locally
	// (break-glass, run by an administrator) and exit.
	ReleaseIsolation  string
	State             string
	DeviceURL         string
	Run               bool
	HeartbeatInterval time.Duration
	Service           bool
	LogDirectory      string
	Inventory         bool
	InventoryInterval time.Duration
	DiskSpace         bool
	Memory            bool
	CPU               bool
	Uptime            bool
	Services          bool
	EventLogs         bool
	WindowsUpdates    bool
	Software          bool
	Sessions          bool
	LocalAccounts     bool
	Response          bool
	Processes         bool
	Scripts           bool
	Desktop           bool
	Terminal          bool
	Files             bool
}

type Env func(string) string

func value(env Env, key, fallback string) string {
	if v := env(key); v != "" {
		return v
	}
	return fallback
}

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	// Flag errors can contain raw input. Callers print fixed usage and safe errors.
	f.SetOutput(io.Discard)
	return f
}

func parse(f *flag.FlagSet, args []string) error {
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return flag.ErrHelp
		}
		return errors.New("invalid command-line arguments; use -help for usage")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments; use -help for usage")
	}
	return nil
}

func level(text string) (slog.Level, error) {
	switch text {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, errors.New("log level must be debug, info, warn, or error")
	}
}

var releaseKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

var acmeDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

func LoadServer(args []string, env Env) (Server, error) {
	var c Server
	f := flags("openrmm-server")
	f.StringVar(&c.Listen, "listen", value(env, "OPENRMM_SERVER_LISTEN", "127.0.0.1:8443"), "listen address")
	f.StringVar(&c.CertFile, "tls-cert", value(env, "OPENRMM_SERVER_TLS_CERT", ".local/tls/server.pem"), "server certificate")
	f.StringVar(&c.KeyFile, "tls-key", value(env, "OPENRMM_SERVER_TLS_KEY", ".local/tls/server-key.pem"), "server private key")
	f.StringVar(&c.CAFile, "tls-ca", value(env, "OPENRMM_SERVER_TLS_CA", ""), "CA that issued the server certificate, written into agent installers; empty uses the agents' system trust")
	f.StringVar(&c.Database, "database", value(env, "OPENRMM_SERVER_DATABASE", ".local/data/openrmm.db"), "database file")
	f.BoolVar(&c.StorageInfo, "storage-info", false, "print local storage information and exit")
	f.StringVar(&c.EncryptionKey, "encryption-key", value(env, "OPENRMM_SERVER_ENCRYPTION_KEY", ".local/secrets/admin-key.bin"), "separate administrator encryption key file")
	f.BoolVar(&c.AdminSetup, "admin-setup", false, "local administrator setup through JSON on stdin")
	f.BoolVar(&c.AdminConfirm, "admin-confirm", false, "local MFA confirmation through JSON on stdin")
	f.BoolVar(&c.AdminReset, "admin-reset", false, "local administrator recovery through JSON on stdin")
	f.BoolVar(&c.Health, "health", false, "check that the server on the listen address is ready, then exit")
	f.BoolVar(&c.AdminLink, "admin-link", false, "print a one-time link token for creating the first administrator in the browser (valid 1 hour)")
	f.StringVar(&c.DeviceListen, "device-listen", value(env, "OPENRMM_SERVER_DEVICE_LISTEN", "127.0.0.1:8444"), "client-certificate-required agent listener")
	f.StringVar(&c.AlertSMTPConfig, "alert-smtp-config", value(env, "OPENRMM_SERVER_ALERT_SMTP_CONFIG", ""), "protected optional SMTP JSON file; empty disables email")
	f.StringVar(&c.DeviceAuthority, "device-authority", value(env, "OPENRMM_SERVER_DEVICE_AUTHORITY", ".local/secrets/device-ca/authority.pem"), "separate device certificate authority file")
	f.StringVar(&c.EvidenceDir, "evidence-dir", value(env, "OPENRMM_SERVER_EVIDENCE_DIR", ".local/evidence"), "evidence store directory (keep it on its own volume)")
	evidenceQuota := f.String("evidence-quota-gb", value(env, "OPENRMM_SERVER_EVIDENCE_QUOTA_GB", "100"), "total evidence quota in GiB; 0 means no quota")
	offlineAfter := f.String("offline-after", value(env, "OPENRMM_SERVER_OFFLINE_AFTER", "120s"), "mark active devices offline after this heartbeat age")
	containerNetwork := f.String("container-network", value(env, "OPENRMM_SERVER_CONTAINER_NETWORK", "false"), "allow wildcard binding inside a container")
	logLevel := f.String("log-level", value(env, "OPENRMM_LOG_LEVEL", "info"), "log level")
	f.StringVar(&c.ACMEDomain, "acme-domain", value(env, "OPENRMM_SERVER_ACME_DOMAIN", ""), "domain name for an automatic HTTPS certificate from an ACME CA (dashboard on port 443); empty uses the certificate files")
	f.StringVar(&c.ACMEEmail, "acme-email", value(env, "OPENRMM_SERVER_ACME_EMAIL", ""), "contact email for the ACME account (optional)")
	f.StringVar(&c.ACMEDirectory, "acme-directory", value(env, "OPENRMM_SERVER_ACME_DIRECTORY", ""), "ACME directory URL; empty uses Let's Encrypt")
	f.StringVar(&c.ACMECache, "acme-cache", value(env, "OPENRMM_SERVER_ACME_CACHE", ""), "folder for the ACME account and certificate; empty uses acme next to the database")
	serverHosts := f.String("server-hosts", value(env, "OPENRMM_SERVER_HOSTS", ""), "comma-separated host names or IP addresses for a certificate from the server's own CA (LAN installs); empty uses acme-domain or the certificate files")
	f.StringVar(&c.ServerCADir, "server-ca-dir", value(env, "OPENRMM_SERVER_CA_DIR", ""), "folder for the server's own CA and certificate; empty uses server-ca next to the encryption key")
	f.StringVar(&c.PublicURL, "public-url", value(env, "OPENRMM_SERVER_PUBLIC_URL", ""), "dashboard address agents enroll with, stored in the installer settings when they are empty")
	f.StringVar(&c.PublicDeviceURL, "public-device-url", value(env, "OPENRMM_SERVER_PUBLIC_DEVICE_URL", ""), "agent address, stored in the installer settings when they are empty")
	f.StringVar(&c.UpdaterDir, "updater-dir", value(env, "OPENRMM_SERVER_UPDATER_DIR", ""), "folder shared with the update sidecar; empty disables updates from the dashboard")
	releaseKeys := f.String("release-keys", value(env, "OPENRMM_SERVER_RELEASE_KEYS", ""), "comma-separated extra public keys (hex) trusted for server releases")
	if err := parse(f, args); err != nil {
		return Server{}, err
	}
	for _, k := range strings.Split(*releaseKeys, ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		if !releaseKey.MatchString(k) || len(c.ReleaseKeys) >= 7 {
			return Server{}, errors.New("release-keys must be up to seven 64-character hex public keys")
		}
		c.ReleaseKeys = append(c.ReleaseKeys, k)
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return Server{}, errors.New("listen address must contain a literal loopback IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return Server{}, errors.New("listen address must contain a literal IP and port")
	}
	c.ContainerNetwork, err = strconv.ParseBool(*containerNetwork)
	if err != nil {
		return Server{}, errors.New("container-network must be true or false")
	}
	if !ip.IsLoopback() && !(c.ContainerNetwork && ip.IsUnspecified()) {
		return Server{}, errors.New("this development server requires a literal loopback listen address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Server{}, errors.New("listen port must be between 1 and 65535")
	}
	c.ServerHosts = lancert.ParseHosts(*serverHosts)
	if len(c.ServerHosts) > 0 {
		if c.ACMEDomain != "" {
			return Server{}, errors.New("use either acme-domain or server-hosts, not both")
		}
		if len(c.ServerHosts) > 20 {
			return Server{}, errors.New("server-hosts allows at most 20 names or addresses")
		}
		for _, h := range c.ServerHosts {
			if !lancert.ValidHost(h) {
				return Server{}, errors.New("server-hosts must be host names or IP addresses separated by commas")
			}
		}
		if c.ServerCADir == "" {
			c.ServerCADir = filepath.Join(filepath.Dir(c.EncryptionKey), "server-ca")
		}
		// Agents trust the server's own CA.
		c.CAFile = filepath.Join(c.ServerCADir, "ca.pem")
	}
	if (c.PublicURL == "") != (c.PublicDeviceURL == "") {
		return Server{}, errors.New("set both public-url and public-device-url, or neither")
	}
	if c.PublicURL != "" {
		server, ok1 := protocol.HTTPSOrigin(c.PublicURL)
		device, ok2 := protocol.HTTPSOrigin(c.PublicDeviceURL)
		if !ok1 || !ok2 || server == device {
			return Server{}, errors.New("public-url and public-device-url must be two different HTTPS addresses without a path")
		}
		c.PublicURL, c.PublicDeviceURL = server, device
	}
	if c.ACMEDomain != "" {
		c.ACMEDomain = strings.ToLower(strings.TrimSuffix(c.ACMEDomain, "."))
		if !acmeDomain.MatchString(c.ACMEDomain) || len(c.ACMEDomain) > 253 {
			return Server{}, errors.New("acme-domain must be a DNS name such as rmm.example.com")
		}
		if c.ACMEDirectory != "" && !strings.HasPrefix(c.ACMEDirectory, "https://") {
			return Server{}, errors.New("acme-directory must be an https URL")
		}
		if c.ACMEEmail != "" && (len(c.ACMEEmail) > 254 || !strings.Contains(c.ACMEEmail, "@") || strings.ContainsAny(c.ACMEEmail, " \r\n")) {
			return Server{}, errors.New("acme-email must be an email address")
		}
		if c.ACMECache == "" {
			c.ACMECache = filepath.Join(filepath.Dir(c.Database), "acme")
		}
	} else if len(c.ServerHosts) == 0 && (c.CertFile == "" || c.KeyFile == "") {
		return Server{}, errors.New("both TLS certificate and key paths are required (or use acme-domain or server-hosts)")
	}
	if c.Database == "" {
		return Server{}, errors.New("a database file path is required")
	}
	if c.EncryptionKey == "" {
		return Server{}, errors.New("an administrator encryption key path is required")
	}
	deviceHost, devicePort, deviceErr := net.SplitHostPort(c.DeviceListen)
	deviceIP, ipErr := netip.ParseAddr(deviceHost)
	devicePortNumber, portErr := strconv.Atoi(devicePort)
	if deviceErr != nil || ipErr != nil || deviceIP.Zone() != "" || !(deviceIP.IsLoopback() || c.ContainerNetwork && deviceIP.IsUnspecified()) || portErr != nil || devicePortNumber < 1 || devicePortNumber > 65535 || c.DeviceListen == c.Listen {
		return Server{}, errors.New("device-listen must be a separate literal loopback IP and valid port; wildcard binding requires container-network")
	}
	if strings.TrimSpace(c.DeviceAuthority) == "" {
		return Server{}, errors.New("a device authority path is required")
	}
	modes := 0
	for _, enabled := range []bool{c.StorageInfo, c.AdminSetup, c.AdminConfirm, c.AdminReset, c.AdminLink, c.Health} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		return Server{}, errors.New("choose only one local administrative operation")
	}
	c.LogLevel, err = level(*logLevel)
	if err != nil {
		return Server{}, err
	}
	quota, err := strconv.ParseInt(*evidenceQuota, 10, 64)
	if err != nil || quota < 0 || quota > 1<<20 {
		return Server{}, errors.New("evidence-quota-gb must be a whole number of GiB between 0 and 1048576")
	}
	c.EvidenceQuota = quota << 30
	if strings.TrimSpace(c.EvidenceDir) == "" {
		return Server{}, errors.New("an evidence directory is required")
	}
	c.OfflineAfter, err = time.ParseDuration(*offlineAfter)
	if err != nil || c.OfflineAfter < 3*time.Second || c.OfflineAfter > 24*time.Hour {
		return Server{}, errors.New("offline-after must be between 3s and 24h")
	}
	return c, err
}

func LoadAgent(args []string, env Env) (Agent, error) {
	var c Agent
	f := flags("openrmm-agent")
	f.StringVar(&c.ServerURL, "server", value(env, "OPENRMM_AGENT_SERVER_URL", "https://127.0.0.1:8443"), "server URL")
	f.StringVar(&c.CAFile, "ca", value(env, "OPENRMM_AGENT_CA", ".local/tls/ca.pem"), "trusted server CA")
	f.BoolVar(&c.Ready, "ready", false, "check storage readiness instead of liveness")
	f.BoolVar(&c.Enroll, "enroll", false, "enroll using a token supplied as JSON on stdin")
	f.BoolVar(&c.Connect, "connect", false, "authenticate once using saved device credentials")
	f.BoolVar(&c.Renew, "renew", false, "renew saved credentials when within seven days of expiry")
	f.StringVar(&c.ReleaseIsolation, "release-isolation", "", "lift network isolation with the release code shown in the dashboard, then exit")
	f.BoolVar(&c.Run, "run", false, "run console heartbeats and automatic credential renewal until stopped")
	f.BoolVar(&c.Service, "service", false, "run under the Windows service controller")
	f.StringVar(&c.LogDirectory, "log-directory", "", "protected service log directory")
	heartbeatInterval := f.String("heartbeat-interval", value(env, "OPENRMM_AGENT_HEARTBEAT_INTERVAL", "30s"), "delay between successful heartbeats")
	inventoryEnabled := f.String("inventory", value(env, "OPENRMM_AGENT_INVENTORY", "true"), "enable the inventory module")
	inventoryInterval := f.String("inventory-interval", value(env, "OPENRMM_AGENT_INVENTORY_INTERVAL", "15m"), "delay between inventory collections")
	diskSpaceEnabled := f.String("disk-space", value(env, "OPENRMM_AGENT_DISK_SPACE", "true"), "enable system-drive disk space reporting every five minutes")
	memoryEnabled := f.String("memory", value(env, "OPENRMM_AGENT_MEMORY", "true"), "enable physical RAM reporting every minute")
	cpuEnabled := f.String("cpu", value(env, "OPENRMM_AGENT_CPU", "true"), "enable overall CPU sampling every minute")
	updatesEnabled := f.String("windows-updates", value(env, "OPENRMM_AGENT_WINDOWS_UPDATES", "true"), "enable Windows Update management through the optional local broker")
	eventLogsEnabled := f.String("event-logs", value(env, "OPENRMM_AGENT_EVENT_LOGS", "true"), "enable on-demand event log queries")
	servicesEnabled := f.String("services", value(env, "OPENRMM_AGENT_SERVICES", "true"), "enable Windows service snapshots and permitted actions")
	uptimeEnabled := f.String("uptime", value(env, "OPENRMM_AGENT_UPTIME", "true"), "enable Windows session uptime reporting every minute")
	scriptsEnabled := f.String("scripts", value(env, "OPENRMM_AGENT_SCRIPTS", "true"), "enable PowerShell script execution")
	terminalEnabled := f.String("terminal", value(env, "OPENRMM_AGENT_TERMINAL", "true"), "enable the interactive PowerShell terminal")
	desktopEnabled := f.String("desktop", value(env, "OPENRMM_AGENT_DESKTOP", "true"), "enable remote desktop (installed Windows service only)")
	filesEnabled := f.String("files", value(env, "OPENRMM_AGENT_FILES", "true"), "enable file browsing and transfer on local fixed drives")
	processesEnabled := f.String("processes", value(env, "OPENRMM_AGENT_PROCESSES", "true"), "report and locally delegated termination of Windows processes")
	softwareEnabled := f.String("software", value(env, "OPENRMM_AGENT_SOFTWARE", "true"), "enable machine-wide software inventory every fifteen minutes")
	sessionsEnabled := f.String("sessions", value(env, "OPENRMM_AGENT_SESSIONS", "true"), "report signed-in Windows sessions every minute")
	responseEnabled := f.String("response", value(env, "OPENRMM_AGENT_RESPONSE", "true"), "enable incident response: evidence collection for cases")
	accountsEnabled := f.String("local-accounts", value(env, "OPENRMM_AGENT_LOCAL_ACCOUNTS", "true"), "report local accounts and privileged group members every fifteen minutes")
	f.StringVar(&c.State, "state", value(env, "OPENRMM_AGENT_STATE", ".local/agent"), "private agent state directory")
	f.StringVar(&c.DeviceURL, "device-server", value(env, "OPENRMM_AGENT_DEVICE_URL", "https://127.0.0.1:8444"), "HTTPS origin for enrolled-agent traffic")
	timeout := f.String("timeout", value(env, "OPENRMM_AGENT_TIMEOUT", "5s"), "request timeout")
	logLevel := f.String("log-level", value(env, "OPENRMM_LOG_LEVEL", "info"), "log level")
	if err := parse(f, args); err != nil {
		return Agent{}, err
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return Agent{}, errors.New("server URL must be an HTTPS origin without credentials, query, fragment, or path")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return Agent{}, errors.New("server URL port must be between 1 and 65535")
		}
	}
	if c.CAFile == "" {
		return Agent{}, errors.New("a trusted CA file is required")
	}
	deviceURL, deviceErr := url.Parse(c.DeviceURL)
	if deviceErr != nil || deviceURL.Scheme != "https" || deviceURL.Hostname() == "" || deviceURL.User != nil || deviceURL.RawQuery != "" || deviceURL.ForceQuery || deviceURL.Fragment != "" || deviceURL.Opaque != "" || deviceURL.Path != "" && deviceURL.Path != "/" {
		return Agent{}, errors.New("device-server must be an HTTPS origin without credentials, query, fragment, or path")
	}
	if deviceURL.Port() != "" {
		port, err := strconv.Atoi(deviceURL.Port())
		if err != nil || port < 1 || port > 65535 {
			return Agent{}, errors.New("device-server port must be between 1 and 65535")
		}
	}
	// Store bare origins: a trailing "/" would otherwise produce "//api" paths.
	c.ServerURL = u.Scheme + "://" + u.Host
	c.DeviceURL = deviceURL.Scheme + "://" + deviceURL.Host
	if strings.TrimSpace(c.State) == "" {
		return Agent{}, errors.New("an agent state directory is required")
	}
	modes := 0
	for _, mode := range []bool{c.Ready, c.Enroll, c.Connect, c.Renew, c.Run, c.Service, c.ReleaseIsolation != ""} {
		if mode {
			modes++
		}
	}
	if modes > 1 {
		return Agent{}, errors.New("choose only one of ready, enroll, connect, renew, run, service, or release-isolation")
	}
	if c.Service && (!filepath.IsAbs(c.State) || !filepath.IsAbs(c.LogDirectory) || filepath.Clean(c.State) == filepath.Clean(c.LogDirectory)) {
		return Agent{}, errors.New("service requires separate absolute state and log-directory paths")
	}
	if !c.Service && c.LogDirectory != "" {
		return Agent{}, errors.New("log-directory is only available in service mode")
	}
	c.Timeout, err = time.ParseDuration(*timeout)
	if err != nil || c.Timeout < time.Second || c.Timeout > time.Minute {
		return Agent{}, errors.New("request timeout must be between 1s and 1m")
	}
	c.LogLevel, err = level(*logLevel)
	if err != nil {
		return Agent{}, err
	}
	c.HeartbeatInterval, err = time.ParseDuration(*heartbeatInterval)
	if err != nil || c.HeartbeatInterval < time.Second || c.HeartbeatInterval > 5*time.Minute {
		return Agent{}, errors.New("heartbeat-interval must be between 1s and 5m")
	}
	c.Inventory, err = strconv.ParseBool(*inventoryEnabled)
	if err != nil {
		return Agent{}, errors.New("inventory must be true or false")
	}
	c.InventoryInterval, err = time.ParseDuration(*inventoryInterval)
	if err != nil || c.InventoryInterval < time.Minute || c.InventoryInterval > 15*time.Minute {
		return Agent{}, errors.New("inventory-interval must be between 1m and 15m")
	}
	c.DiskSpace, err = strconv.ParseBool(*diskSpaceEnabled)
	if err != nil {
		return Agent{}, errors.New("disk-space must be true or false")
	}
	c.Memory, err = strconv.ParseBool(*memoryEnabled)
	if err != nil {
		return Agent{}, errors.New("memory must be true or false")
	}
	c.CPU, err = strconv.ParseBool(*cpuEnabled)
	if err != nil {
		return Agent{}, errors.New("cpu must be true or false")
	}
	c.WindowsUpdates, err = strconv.ParseBool(*updatesEnabled)
	if err != nil {
		return Agent{}, errors.New("windows-updates must be true or false")
	}
	c.EventLogs, err = strconv.ParseBool(*eventLogsEnabled)
	if err != nil {
		return Agent{}, errors.New("event-logs must be true or false")
	}
	c.Services, err = strconv.ParseBool(*servicesEnabled)
	if err != nil {
		return Agent{}, errors.New("services must be true or false")
	}
	c.Uptime, err = strconv.ParseBool(*uptimeEnabled)
	if err != nil {
		return Agent{}, errors.New("uptime must be true or false")
	}
	c.Scripts, err = strconv.ParseBool(*scriptsEnabled)
	if err != nil {
		return Agent{}, errors.New("scripts must be true or false")
	}
	c.Terminal, err = strconv.ParseBool(*terminalEnabled)
	if err != nil {
		return Agent{}, errors.New("terminal must be true or false")
	}
	c.Desktop, err = strconv.ParseBool(*desktopEnabled)
	if err != nil {
		return Agent{}, errors.New("desktop must be true or false")
	}
	// The desktop companion connects only to the installed service.
	c.Desktop = c.Desktop && c.Service
	c.Files, err = strconv.ParseBool(*filesEnabled)
	if err != nil {
		return Agent{}, errors.New("files must be true or false")
	}
	c.Processes, err = strconv.ParseBool(*processesEnabled)
	if err != nil {
		return Agent{}, errors.New("processes must be true or false")
	}
	c.Software, err = strconv.ParseBool(*softwareEnabled)
	if err != nil {
		return Agent{}, errors.New("software must be true or false")
	}
	c.Sessions, err = strconv.ParseBool(*sessionsEnabled)
	if err != nil {
		return Agent{}, errors.New("sessions must be true or false")
	}
	c.LocalAccounts, err = strconv.ParseBool(*accountsEnabled)
	if err != nil {
		return Agent{}, errors.New("local-accounts must be true or false")
	}
	c.Response, err = strconv.ParseBool(*responseEnabled)
	if err != nil {
		return Agent{}, errors.New("response must be true or false")
	}
	return c, err
}
