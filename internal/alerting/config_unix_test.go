//go:build !windows

package alerting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSMTPRejectsPublicCredentialMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "smtp.json")
	c := MailConfig{Host: "localhost", Port: 587, TLS: "starttls", From: "rmm@example.invalid", To: []string{"admin@example.invalid"}, ServerURL: "https://rmm.example.invalid"}
	b, _ := json.Marshal(c)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, e := LoadMailer(path); e != nil {
		t.Fatal(e)
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("fixture")
	}
	if _, e := LoadMailer(path); e == nil {
		t.Fatal("world-readable credentials accepted")
	}
}
