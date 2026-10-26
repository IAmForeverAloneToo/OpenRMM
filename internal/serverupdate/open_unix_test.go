//go:build unix

package serverupdate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A server that controls the exchange volume cannot stall or exhaust the
// updater with a FIFO, a symbolic link or an endless file.
func TestExchangeRefusesSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.json")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link.json")
	if e := os.Symlink("/dev/zero", link); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{fifo, link} {
		done := make(chan error, 1)
		go func() {
			var v map[string]any
			done <- readJSON(p, &v, 1024)
		}()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("special file accepted", p)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reading a special file blocked", p)
		}
	}
	if _, e := hashFile(link); e == nil {
		t.Fatal("hashFile followed a symbolic link")
	}
}
