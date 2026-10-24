package alerting

import (
	"encoding/json"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestSMTPRejectsUnrelatedFileReaders(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if e := devtls.Generate(dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "smtp.json")
	c := MailConfig{Host: "localhost", Port: 587, TLS: "starttls", From: "rmm@example.invalid", To: []string{"admin@example.invalid"}, ServerURL: "https://rmm.example.invalid"}
	b, _ := json.Marshal(c)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("fixture")
	}
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		t.Fatal(e)
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + u.User.Sid.String() + ")(A;;FA;;;SY)(A;;GR;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		t.Fatal(e)
	}
	if e = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadMailer(path); e == nil {
		t.Fatal("world-readable SMTP credentials accepted")
	}
}
