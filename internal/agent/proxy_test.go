package agent

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
)

func TestParseProxy(t *testing.T) {
	for value, want := range map[string]string{
		"":                                 "none",
		"DIRECT":                           "direct",
		"proxy.lan:8080":                   "http://proxy.lan:8080",
		"http://user:p%40ss@10.0.0.5:3128": "http://10.0.0.5:3128",
		"https://proxy.lan/":               "https://proxy.lan",
		"http://[fd00::1]:8080":            "http://[fd00::1]:8080",
	} {
		p, err := parseProxy(value)
		if err != nil || p.String() != want {
			t.Errorf("parseProxy(%q) = %s, %v; want %s", value, p, err, want)
		}
	}
	for _, value := range []string{"socks5://proxy:1080", "http://proxy/path", "http://proxy:8080?x=1", "http://", "proxy lan:8080", strings.Repeat("a", 600)} {
		if _, err := parseProxy(value); err == nil {
			t.Errorf("parseProxy(%q) accepted", value)
		}
	}
	p, _ := parseProxy("http://user:secret@proxy:8080")
	if strings.Contains(p.String(), "secret") || p.url.User.Username() != "user" {
		t.Fatal("password shown or user lost")
	}
}

func TestSystemProxy(t *testing.T) {
	s := parseSystemProxy("http=plain:80;https=secure:8443", "<local>;*.corp.example;10.*")
	if u := s.forHost("rmm.example.com"); u == nil || u.Host != "secure:8443" {
		t.Fatal("HTTPS entry not used", u)
	}
	for _, host := range []string{"rmm", "rmm.corp.example", "10.1.2.3", "RMM.CORP.EXAMPLE"} {
		if s.forHost(host) != nil {
			t.Error("bypass ignored for", host)
		}
	}
	if u := parseSystemProxy("proxy:3128", "").forHost("rmm"); u == nil || u.Host != "proxy:3128" {
		t.Fatal("plain entry not used", u)
	}
	if parseSystemProxy("http=plain:80", "").forHost("rmm.example.com") != nil {
		t.Fatal("an HTTP-only proxy used for HTTPS")
	}
	if parseSystemProxy("", "").forHost("x") != nil || parseSystemProxy("http://user:pw@proxy:80", "").url != nil {
		t.Fatal("empty or invalid list produced a proxy")
	}
	for pattern, host := range map[string]string{"*": "a", "a*c": "abc", "*.lan": "x.lan", "10.*.1": "10.0.0.1"} {
		if !wildcard(pattern, host) {
			t.Error("no match", pattern, host)
		}
	}
	if wildcard("*.lan", "lan") || wildcard("a*c", "abd") {
		t.Fatal("wrong match")
	}
}

func withProxySources(t *testing.T, policy string, system systemProxy) {
	t.Helper()
	oldPolicy, oldSystem := readPolicyProxy, readMachineProxy
	readPolicyProxy = func() string { return policy }
	readMachineProxy = func() systemProxy { return system }
	proxies.reset()
	t.Cleanup(func() { readPolicyProxy, readMachineProxy = oldPolicy, oldSystem; proxies.reset() })
}

func TestProxyPrecedenceAndHandoff(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the installer setting is protected with DPAPI")
	}
	root := t.TempDir()
	c := config.Agent{State: filepath.Join(root, "state")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	target, _ := url.Parse("https://rmm.example.com:8444")
	withProxySources(t, "", parseSystemProxy("system:8080", ""))
	if u, source := proxies.forURL(c.State, target); u == nil || u.Host != "system:8080" || source != "Windows proxy" {
		t.Fatal("Windows proxy not used", u, source)
	}
	handoff := filepath.Join(root, proxyHandoff)
	if err := os.WriteFile(handoff, []byte("\ufeffhttp://user:secret@installer:3128\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	applyProxyHandoff(c, logger)
	if _, err := os.Stat(handoff); !os.IsNotExist(err) {
		t.Fatal("handoff file kept")
	}
	if b, err := os.ReadFile(filepath.Join(c.State, proxyStateFile)); err != nil || strings.Contains(string(b), "secret") {
		t.Fatal("setting not saved protected", err)
	}
	if u, _ := proxies.forURL(c.State, target); u == nil || u.Host != "installer:3128" || u.User.String() != "user:secret" {
		t.Fatal("installer setting not used", u)
	}
	if !strings.Contains(proxies.describe(c.State, target.String()), "http://installer:3128 (installer setting)") || strings.Contains(proxies.describe(c.State, target.String()), "secret") {
		t.Fatal("description wrong", proxies.describe(c.State, target.String()))
	}
	// An invalid handoff keeps the previous setting.
	_ = os.WriteFile(handoff, []byte("ftp://nope"), 0600)
	applyProxyHandoff(c, logger)
	if u, _ := proxies.forURL(c.State, target); u == nil || u.Host != "installer:3128" {
		t.Fatal("invalid handoff replaced the setting")
	}
	withProxySources(t, "direct", parseSystemProxy("system:8080", ""))
	if u, source := proxies.forURL(c.State, target); u != nil || source != "policy" {
		t.Fatal("policy direct not applied", u, source)
	}
	withProxySources(t, "not a proxy", parseSystemProxy("", ""))
	if u, _ := proxies.forURL(c.State, target); u == nil || !strings.Contains(proxies.describe(c.State, target.String()), "policy value Proxy is invalid") {
		t.Fatal("invalid policy not reported and skipped")
	}
	_ = os.WriteFile(handoff, []byte("none"), 0600)
	applyProxyHandoff(c, logger)
	if u, _ := proxies.forURL(c.State, target); u != nil {
		t.Fatal("setting not removed", u)
	}
}

// The agent's transports send server requests through the proxy as a
// CONNECT tunnel with Basic authentication.
func TestRequestsUseProxy(t *testing.T) {
	var connect, auth string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connect, auth = r.Method+" "+r.Host, r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("user", "secret")
	withProxySources(t, u.String(), systemProxy{})
	c := config.Agent{State: t.TempDir(), Timeout: 5e9}
	var out struct{}
	_ = requestJSON(t.Context(), c, nil, "https://rmm.example.com:8444", "GET", "/api/v1/agent/identity", nil, &out)
	if connect != "CONNECT rmm.example.com:8444" || auth != "Basic dXNlcjpzZWNyZXQ=" {
		t.Fatalf("request did not use the proxy: %q %q", connect, auth)
	}
}
