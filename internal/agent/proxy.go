package agent

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/applications"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/dpapi"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// The agent reaches its server through a proxy when one is set, first match:
//  1. the machine policy: string "Proxy" in HKLM\SOFTWARE\Policies\OpenRMM\Agent
//     (Group Policy; readable by every user, so better without a password);
//  2. the installer's setting (install.cmd /proxy), kept protected in the
//     state folder;
//  3. the machine's WinHTTP proxy (netsh winhttp set proxy) and its bypass
//     list.
//
// "direct" in 1 or 2 means no proxy. TLS to the server runs end to end
// through the proxy (CONNECT), so the proxy cannot read or change it, and a
// proxy password is sent as Basic authentication.

// proxyHandoff is the installer's setting in the data folder (SYSTEM and
// Administrators only); the service moves it into proxyStateFile.
const (
	proxyHandoff   = "proxy.txt"
	proxyStateFile = "proxy.bin"
	proxyPurpose   = "agent-proxy:v1"
)

// proxySetting is one source's choice: unset, direct, or a proxy.
type proxySetting struct {
	set    bool
	direct bool
	url    *url.URL
}

func parseProxy(value string) (proxySetting, error) {
	value = strings.TrimSpace(value)
	invalid := errors.New("proxy must be direct or http://[user:password@]host:port")
	switch {
	case value == "":
		return proxySetting{}, nil
	case strings.EqualFold(value, "direct"):
		return proxySetting{set: true, direct: true}, nil
	case len(value) > 512 || strings.ContainsAny(value, " \t\r\n"):
		return proxySetting{}, invalid
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return proxySetting{}, invalid
	}
	u.Path = ""
	return proxySetting{set: true, url: u}, nil
}

// String names the proxy without its password, for logs.
func (p proxySetting) String() string {
	switch {
	case !p.set:
		return "none"
	case p.direct:
		return "direct"
	}
	return p.url.Scheme + "://" + p.url.Host
}

// proxyResolver caches the sources for a few minutes, so a changed policy
// or WinHTTP setting applies without a restart.
type proxyResolver struct {
	mu      sync.Mutex
	state   string
	checked time.Time
	policy  proxySetting
	stored  proxySetting
	system  systemProxy
	// problems lists sources that were set but unreadable (ignored).
	problems []string
}

var proxies = &proxyResolver{}

// The machine sources; tests replace them.
var (
	readPolicyProxy  = policyProxy
	readMachineProxy = machineProxy
)

const proxyRefresh = 5 * time.Minute

// proxyFunc is the Proxy function of every agent transport to the server.
func proxyFunc(state string) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		u, _ := proxies.forURL(state, r.URL)
		return u, nil
	}
}

func (p *proxyResolver) refresh(state string) {
	if p.state == state && time.Since(p.checked) < proxyRefresh {
		return
	}
	p.state, p.checked, p.problems = state, time.Now(), nil
	var err error
	if p.policy, err = parseProxy(readPolicyProxy()); err != nil {
		p.problems = append(p.problems, "the policy value Proxy is invalid")
	}
	p.stored = proxySetting{}
	if b, e := readLimited(filepath.Join(state, proxyStateFile), 4096); e == nil {
		plain, e := dpapi.Unprotect(b, proxyPurpose)
		if e == nil {
			p.stored, e = parseProxy(string(plain))
		}
		if e != nil {
			p.problems = append(p.problems, "the installer's proxy setting cannot be read")
		}
	}
	p.system = readMachineProxy()
}

// forURL returns the proxy for a request to target (nil: direct) and where
// the choice came from.
func (p *proxyResolver) forURL(state string, target *url.URL) (*url.URL, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(state)
	for _, s := range []struct {
		setting proxySetting
		source  string
	}{{p.policy, "policy"}, {p.stored, "installer setting"}} {
		if s.setting.set {
			if s.setting.direct {
				return nil, s.source
			}
			return s.setting.url, s.source
		}
	}
	if u := p.system.forHost(target.Hostname()); u != nil {
		return u, "Windows proxy"
	}
	return nil, "default"
}

// describe summarizes the proxy used for origin, for the log.
func (p *proxyResolver) describe(state, origin string) string {
	target, err := url.Parse(origin)
	if err != nil {
		return "unknown"
	}
	u, source := p.forURL(state, target)
	p.mu.Lock()
	problems := strings.Join(p.problems, "; ")
	p.mu.Unlock()
	text := "direct (" + source + ")"
	if u != nil {
		text = proxySetting{set: true, url: u}.String() + " (" + source + ")"
	}
	if problems != "" {
		text += "; ignored: " + problems
	}
	return text
}

// reset makes the next request read the sources again.
func (p *proxyResolver) reset() {
	p.mu.Lock()
	p.checked = time.Time{}
	p.mu.Unlock()
}

// systemProxy is the machine's WinHTTP proxy for HTTPS and its bypass list.
type systemProxy struct {
	url    *url.URL
	bypass []string
}

// parseSystemProxy reads WinHTTP's proxy list ("host:port", or per scheme
// "http=host:port;https=host:port") and bypass list ("<local>;*.lan;10.*").
func parseSystemProxy(list, bypass string) systemProxy {
	fields := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n' })
	}
	var plain, secure string
	for _, entry := range fields(list) {
		scheme, value, labeled := strings.Cut(entry, "=")
		switch {
		case !labeled && plain == "":
			plain = entry
		case labeled && strings.EqualFold(scheme, "https") && secure == "":
			secure = value
		}
	}
	chosen := secure
	if chosen == "" {
		chosen = plain
	}
	// The proxy itself is reached over plain HTTP; the server's TLS runs
	// inside the tunnel.
	chosen = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(chosen), "http://"), "https://")
	p, err := parseProxy(chosen)
	if err != nil || !p.set || p.direct || p.url.User != nil {
		return systemProxy{}
	}
	return systemProxy{url: p.url, bypass: fields(strings.ToLower(bypass))}
}

func (s systemProxy) forHost(host string) *url.URL {
	if s.url == nil {
		return nil
	}
	host = strings.ToLower(host)
	for _, pattern := range s.bypass {
		if pattern == "<local>" && !strings.Contains(host, ".") || wildcard(pattern, host) {
			return nil
		}
	}
	return s.url
}

// wildcard matches a bypass entry in which * stands for any characters.
func wildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

// applyProxyHandoff moves the installer's proxy setting into the protected
// state folder: "none" removes it, anything else replaces it. The plain file
// is removed either way, an invalid one with an error in the log.
func applyProxyHandoff(c config.Agent, logger *slog.Logger) {
	path := filepath.Join(filepath.Dir(c.State), proxyHandoff)
	b, err := readLimited(path, 1024)
	if err != nil {
		return
	}
	defer func() {
		if os.Remove(path) != nil {
			logger.Error("cannot remove the installer's proxy file")
		}
		proxies.reset()
	}()
	value := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	stored := filepath.Join(c.State, proxyStateFile)
	if strings.EqualFold(value, "none") {
		if err := os.Remove(stored); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Error("cannot remove the proxy setting")
			return
		}
		logger.Info("proxy setting removed by the installer")
		return
	}
	p, err := parseProxy(value)
	if err != nil || !p.set {
		logger.Error("the installer's proxy setting is invalid; keeping the previous one", "reason", "proxy must be none, direct or http://[user:password@]host:port")
		return
	}
	sealed, err := dpapi.Protect([]byte(value), proxyPurpose)
	if err == nil {
		err = os.MkdirAll(c.State, 0700)
	}
	if err == nil {
		err = replaceFile(stored, sealed)
	}
	if err != nil {
		logger.Error("cannot save the installer's proxy setting")
		return
	}
	logger.Info("proxy setting saved from the installer", "proxy", p.String())
}

// replaceFile writes a private file in one step.
func replaceFile(path string, value []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".replace-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	_, writeErr := file.Write(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("cannot write private file")
	}
	return os.Rename(name, path)
}

// scriptProxyFor returns the proxy, with any password, for the download of
// an application installer script; other scripts get none.
func scriptProxyFor(state string, q protocol.ScriptJob) string {
	raw, ok := applications.PackageURL(q.Version.Definition.Body)
	if !ok {
		return ""
	}
	target, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u, _ := proxies.forURL(state, target); u != nil {
		return u.String()
	}
	return ""
}
