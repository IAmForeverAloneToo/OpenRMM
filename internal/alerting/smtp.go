package alerting

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"io"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type MailConfig struct {
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	TLS        string   `json:"tls"`
	Username   string   `json:"username"`
	Password   string   `json:"password"`
	From       string   `json:"from"`
	To         []string `json:"to"`
	ServerURL  string   `json:"server_url"`
	RootCAFile string   `json:"root_ca_file"`
}
type Mailer struct {
	config MailConfig
	roots  *x509.CertPool
	ID     string
}
type Notice struct {
	AlertID, Event, DeviceID, Hostname, Title, Severity, Condition string
	OpenedAt                                                       int64
}
type MailResult struct{ Status, Reason string }

var ErrMailConfig = errors.New("invalid SMTP configuration; check the protected file and TLS trust settings")

func address(s string) bool {
	if len(s) > 254 || s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return false
	}
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	a, e := mail.ParseAddress(s)
	return e == nil && a.Name == "" && a.Address == s
}
func NewMailer(c MailConfig) (*Mailer, error) {
	host := c.Host
	if ip := net.ParseIP(host); ip == nil {
		if len(host) < 1 || len(host) > 253 || strings.Trim(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "" {
			return nil, ErrMailConfig
		}
	}
	if c.Port < 1 || c.Port > 65535 || (c.TLS != "starttls" && c.TLS != "tls") || !address(c.From) || len(c.To) < 1 || len(c.To) > 10 || len(c.Username) > 256 || len(c.Password) > 1024 || !utf8.ValidString(c.Username) || !utf8.ValidString(c.Password) || strings.ContainsAny(c.Username, "\r\n\x00") || (c.Username == "") != (c.Password == "") {
		return nil, ErrMailConfig
	}
	seen := map[string]bool{}
	for _, a := range c.To {
		if !address(a) || seen[a] {
			return nil, ErrMailConfig
		}
		seen[a] = true
	}
	u, e := url.Parse(c.ServerURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrMailConfig
	}
	c.ServerURL = strings.TrimSuffix(c.ServerURL, "/")
	var roots *x509.CertPool
	if c.RootCAFile != "" {
		f, e := os.Open(c.RootCAFile)
		if e != nil {
			return nil, ErrMailConfig
		}
		b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
		f.Close()
		roots = x509.NewCertPool()
		if e != nil || len(b) > 1024*1024 || !roots.AppendCertsFromPEM(b) {
			return nil, ErrMailConfig
		}
	}
	return &Mailer{config: c, roots: roots, ID: ConfigID(c)}, nil
}

// ConfigID fingerprints a configuration's destination (server, sender,
// recipients, link), binding queued notices to it. The password and CA file
// are left out, so the ID can be computed without decrypting anything.
func ConfigID(c MailConfig) string {
	c.ServerURL = strings.TrimSuffix(c.ServerURL, "/")
	c.Password = ""
	c.RootCAFile = ""
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func LoadMailer(path string) (*Mailer, error) {
	if path == "" {
		return nil, nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrMailConfig
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 16*1024 {
		return nil, ErrMailConfig
	}
	if e = privateConfig(path, f); e != nil {
		return nil, ErrMailConfig
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16*1024+1))
	if e != nil || len(raw) > 16*1024 {
		return nil, ErrMailConfig
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var c MailConfig
	if d.Decode(&c) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return nil, ErrMailConfig
	}
	return NewMailer(c)
}
func (m *Mailer) Send(ctx context.Context, n Notice) MailResult {
	result := func(status, reason string) MailResult { return MailResult{status, reason} }
	if m == nil {
		return result("failed", "disabled")
	}
	if !protocol.ValidID(n.AlertID) || !protocol.ValidID(n.DeviceID) || (n.Event != "opened" && n.Event != "resolved") || len(n.Hostname) > 512 || len(n.Title) > 128 || len(n.Condition) > 256 {
		return result("failed", "invalid_notice")
	}
	text := fmt.Sprintf("OpenRMM alert %s\r\n\r\nDevice: %s\r\nDevice ID: %s\r\nAlert: %s\r\nSeverity: %s\r\nCondition: %s\r\nOpened (UTC): %s\r\n\r\n%s/alerts?device=%s\r\n", n.Event, n.Hostname, n.DeviceID, n.Title, n.Severity, n.Condition, time.Unix(n.OpenedAt, 0).UTC().Format(time.RFC3339), m.config.ServerURL, n.DeviceID)
	return m.deliver(ctx, "OpenRMM device alert "+n.Event, "openrmm."+n.AlertID+"."+n.Event, text)
}

// SendTest sends a short test message to the configured recipients, from
// the dashboard's e-mail settings.
func (m *Mailer) SendTest(ctx context.Context, actor string) MailResult {
	if m == nil {
		return MailResult{"failed", "disabled"}
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	text := fmt.Sprintf("This is a test message from OpenRMM, sent by %s from the e-mail settings.\r\nAlert notices will be sent to the same recipients.\r\n\r\n%s/\r\n", actor, m.config.ServerURL)
	return m.deliver(ctx, "OpenRMM test e-mail", "openrmm.test."+hex.EncodeToString(id), text)
}

// deliver sends one plain-text message over the configured TLS connection.
func (m *Mailer) deliver(ctx context.Context, subject, messageID, text string) MailResult {
	result := func(status, reason string) MailResult { return MailResult{status, reason} }
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(m.config.Host, strconv.Itoa(m.config.Port)))
	if e != nil {
		return result("retry", "connection")
	}
	defer conn.Close()
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { rawConn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return result("retry", "connection")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.config.Host, RootCAs: m.roots}
	if m.config.TLS == "tls" {
		secured := tls.Client(conn, tlsConfig)
		if secured.HandshakeContext(ctx) != nil {
			return result("failed", "tls")
		}
		conn = secured
	}
	c, e := smtp.NewClient(conn, m.config.Host)
	if e != nil {
		return mailFailure(e)
	}
	defer c.Close()
	if m.config.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return result("failed", "tls_required")
		}
		if c.StartTLS(tlsConfig) != nil {
			return result("failed", "tls")
		}
	}
	if state, ok := c.TLSConnectionState(); !ok || !state.HandshakeComplete {
		return result("failed", "tls_required")
	}
	if m.config.Username != "" {
		if e = c.Auth(smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)); e != nil {
			return mailFailure(e)
		}
	}
	if e = c.Mail(m.config.From); e != nil {
		return mailFailure(e)
	}
	for _, a := range m.config.To {
		if e = c.Rcpt(a); e != nil {
			return mailFailure(e)
		}
	}
	data, e := c.Data()
	if e != nil {
		return mailFailure(e)
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@openrmm.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", m.config.From, strings.Join(m.config.To, ", "), subject, time.Now().UTC().Format(time.RFC1123Z), messageID)
	w := quotedprintable.NewWriter(&body)
	_, e = io.WriteString(w, text)
	if e != nil || w.Close() != nil {
		return result("failed", "encoding")
	}
	if body.Len() > 8192 {
		return result("failed", "too_large")
	}
	// After DATA starts, a connection loss may hide successful relay acceptance.
	// Never automatically retry that ambiguity. An explicit rejection is known.
	if _, e = data.Write(body.Bytes()); e != nil {
		return result("unknown", "acceptance_unknown")
	}
	if e = data.Close(); e != nil {
		var reply *textproto.Error
		if errors.As(e, &reply) {
			return mailFailure(e)
		}
		return result("unknown", "acceptance_unknown")
	}
	_ = c.Quit()
	return result("sent", "accepted")
}
func mailFailure(e error) MailResult {
	var r *textproto.Error
	if errors.As(e, &r) && r.Code >= 500 {
		return MailResult{"failed", "rejected"}
	}
	return MailResult{"retry", "temporary"}
}
