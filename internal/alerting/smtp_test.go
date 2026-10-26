package alerting

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type captureSMTP struct {
	config  MailConfig
	message chan string
	auth    atomic.Int32
}

func smtpFixture(t *testing.T, mode, behavior string) *captureSMTP {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	if e := devtls.Generate(dir); e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"))
	if e != nil {
		t.Fatal(e)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	f := &captureSMTP{config: MailConfig{Host: "127.0.0.1", Port: p, TLS: mode, Username: "test-user", Password: "test-secret-not-a-real-password", From: "rmm@example.invalid", To: []string{"admin@example.invalid"}, ServerURL: "https://rmm.example.invalid", RootCAFile: filepath.Join(dir, "ca.pem")}, message: make(chan string, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, e := listener.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		var c net.Conn = raw
		encrypted := false
		if mode == "tls" {
			s := tls.Server(c, tlsConfig)
			if s.Handshake() != nil {
				return
			}
			c = s
			encrypted = true
		}
		r := textproto.NewReader(bufio.NewReader(c))
		w := bufio.NewWriter(c)
		say := func(s string) bool {
			if _, e := w.WriteString(s + "\r\n"); e != nil {
				return false
			}
			return w.Flush() == nil
		}
		if !say("220 capture.example.invalid ESMTP") {
			return
		}
		for {
			line, e := r.ReadLine()
			if e != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if !say("250-capture.example.invalid") {
					return
				}
				if !encrypted && behavior != "no-starttls" {
					if !say("250-STARTTLS") {
						return
					}
				}
				if !say("250 AUTH PLAIN") {
					return
				}
			case line == "STARTTLS":
				if !say("220 Begin TLS") {
					return
				}
				s := tls.Server(c, tlsConfig)
				if s.Handshake() != nil {
					return
				}
				c = s
				encrypted = true
				r = textproto.NewReader(bufio.NewReader(c))
				w = bufio.NewWriter(c)
			case strings.HasPrefix(line, "AUTH "):
				if !encrypted {
					return
				}
				f.auth.Add(1)
				if behavior == "reject-auth" {
					say("535 authentication rejected")
				} else {
					say("235 authentication accepted")
				}
			case strings.HasPrefix(line, "MAIL FROM:"):
				say("250 sender OK")
			case strings.HasPrefix(line, "RCPT TO:"):
				if behavior == "temporary" {
					say("450 temporarily unavailable")
				} else {
					say("250 recipient OK")
				}
			case line == "DATA":
				if !say("354 Send message") {
					return
				}
				data, e := io.ReadAll(io.LimitReader(r.DotReader(), 16384))
				if e != nil {
					return
				}
				f.message <- string(data)
				if behavior == "ambiguous" {
					return
				}
				if !say("250 accepted") {
					return
				}
			case line == "QUIT":
				say("221 bye")
				return
			default:
				say("500 unsupported")
			}
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("SMTP capture did not stop")
		}
	})
	return f
}
func testNotice() Notice {
	return Notice{AlertID: strings.Repeat("a", 32), DeviceID: strings.Repeat("b", 32), Event: "opened", Hostname: "node\r\nBcc: intruder@example.invalid", Title: "High CPU usage", Severity: "warning", Condition: "At least 90% usage", OpenedAt: 1800000000}
}
func TestSMTPVerifiedTLSBothModesAndEscapedBody(t *testing.T) {
	for _, mode := range []string{"tls", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			f := smtpFixture(t, mode, "")
			m, e := NewMailer(f.config)
			if e != nil {
				t.Fatal(e)
			}
			r := m.Send(context.Background(), testNotice())
			if r.Status != "sent" || f.auth.Load() != 1 {
				t.Fatal("verified authenticated mail failed", r)
			}
			msg := <-f.message
			parsed, e := mail.ReadMessage(strings.NewReader(msg))
			if e != nil || parsed.Header.Get("Bcc") != "" || parsed.Header.Get("Subject") != "OpenRMM device alert opened" {
				t.Fatal("untrusted body entered headers")
			}
		})
	}
}
func TestSMTPRefusesDowngradeAndUnknownAcceptanceNeverRetry(t *testing.T) {
	for _, c := range []struct{ behavior, status, reason string }{{"no-starttls", "failed", "tls_required"}, {"reject-auth", "failed", "rejected"}, {"temporary", "retry", "temporary"}, {"ambiguous", "unknown", "acceptance_unknown"}} {
		t.Run(c.behavior, func(t *testing.T) {
			f := smtpFixture(t, "starttls", c.behavior)
			m, e := NewMailer(f.config)
			if e != nil {
				t.Fatal(e)
			}
			r := m.Send(context.Background(), testNotice())
			if r.Status != c.status || r.Reason != c.reason {
				t.Fatal("incorrect acceptance classification", r)
			}
			if c.behavior == "no-starttls" && f.auth.Load() != 0 {
				t.Fatal("credentials sent before TLS")
			}
		})
	}
}
func TestSMTPUntrustedCertificateAndConfigurationPrivacy(t *testing.T) {
	f := smtpFixture(t, "tls", "")
	f.config.RootCAFile = ""
	m, e := NewMailer(f.config)
	if e != nil {
		t.Fatal(e)
	}
	r := m.Send(context.Background(), testNotice())
	if r.Status != "failed" || r.Reason != "tls" || f.auth.Load() != 0 {
		t.Fatal("untrusted SMTP accepted", r)
	}

}
func TestSMTPConfigStrictFieldsAndAddressInjection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := devtls.Generate(dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "smtp.json")
	c := MailConfig{Host: "localhost", Port: 587, TLS: "starttls", From: "rmm@example.invalid", To: []string{"admin@example.invalid"}, ServerURL: "https://rmm.example.invalid"}
	data, _ := json.Marshal(c)
	if os.WriteFile(path, data, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e := LoadMailer(path); e != nil {
		t.Fatal("private config refused", e)
	}
	if os.WriteFile(path, []byte(`{"password":"not-real","unexpected":true}`), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e := LoadMailer(path); e == nil || strings.Contains(e.Error(), "not-real") {
		t.Fatal("malformed config accepted or secret leaked")
	}
	c.From = "rmm@example.invalid\r\nBcc: intruder@example.invalid"
	if _, e := NewMailer(c); e == nil {
		t.Fatal("header injection accepted")
	}
}
func TestSMTPTestMessageAndConfigID(t *testing.T) {
	f := smtpFixture(t, "starttls", "")
	m, e := NewMailer(f.config)
	if e != nil {
		t.Fatal(e)
	}
	// The ID ignores the password, the CA file and a trailing slash, so it
	// can be computed from stored settings without decrypting anything.
	other := f.config
	other.Password, other.RootCAFile, other.ServerURL = "", "", other.ServerURL+"/"
	if ConfigID(other) != m.ID {
		t.Fatal("configuration ID depends on the password or CA file")
	}
	other.To = []string{"someone-else@example.invalid"}
	if ConfigID(other) == m.ID {
		t.Fatal("configuration ID ignores the recipients")
	}
	r := m.SendTest(context.Background(), "admin")
	if r.Status != "sent" || f.auth.Load() != 1 {
		t.Fatal("test message failed", r)
	}
	parsed, e := mail.ReadMessage(strings.NewReader(<-f.message))
	if e != nil || parsed.Header.Get("Subject") != "OpenRMM test e-mail" || !strings.HasPrefix(parsed.Header.Get("Message-ID"), "<openrmm.test.") {
		t.Fatal("unexpected test message headers")
	}
	if r := (*Mailer)(nil).SendTest(context.Background(), "admin"); r.Status != "failed" || r.Reason != "disabled" {
		t.Fatal("test message without a mailer", r)
	}
}
