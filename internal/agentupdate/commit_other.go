//go:build !windows

package agentupdate

import (
	"os"
	"path/filepath"
)

func commitJSON(source, destination string) error {
	if e := os.Rename(source, destination); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(destination))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
