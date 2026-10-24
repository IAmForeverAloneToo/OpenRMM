// Package agentinstaller builds the installer ZIP an owner downloads from the
// UI: the unchanged signed agent MSI, its signed release, the
// enrollment file and the setup scripts in setup/.
package agentinstaller

import (
	"archive/zip"
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

//go:embed setup
var setup embed.FS

// Scripts are the setup files, in ZIP order.
var Scripts = []string{"install.cmd", "install.ps1", "README.txt"}

// Write streams the ZIP to w. The MSI (already compressed) is stored as is
// and must be exactly size bytes.
func Write(w io.Writer, msi io.Reader, size int64, release protocol.SignedAgentRelease, enrollment protocol.EnrollmentFile, now time.Time) error {
	z := zip.NewWriter(w)
	add := func(name string, method uint16, body io.Reader) (int64, error) {
		f, e := z.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: now})
		if e != nil {
			return 0, e
		}
		return io.Copy(f, body)
	}
	for _, name := range Scripts {
		b, e := setup.ReadFile("setup/" + name)
		if e != nil {
			return e
		}
		// Windows scripts and Notepad expect CRLF line endings.
		b = bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
		if _, e = add(name, zip.Deflate, bytes.NewReader(b)); e != nil {
			return e
		}
	}
	for _, f := range []struct {
		name  string
		value any
	}{{"release.json", release}, {"enrollment.json", enrollment}} {
		b, e := json.MarshalIndent(f.value, "", "  ")
		if e != nil {
			return e
		}
		if _, e = add(f.name, zip.Deflate, bytes.NewReader(b)); e != nil {
			return e
		}
	}
	n, e := add("openrmm-agent.msi", zip.Store, io.LimitReader(msi, size+1))
	if e != nil {
		return e
	}
	if n != size {
		return errors.New("agent MSI size changed")
	}
	return z.Close()
}
