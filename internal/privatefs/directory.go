// Package privatefs creates application-owned directories with restricted access.
package privatefs

import "os"

// ProtectDirectory applies the same restricted access to an existing,
// application-owned directory (for example one created by Windows Installer).
func ProtectDirectory(path string) error { return restrictDirectory(path) }

// CreateDirectory refuses existing paths. Parent directories must already exist.
func CreateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if err := restrictDirectory(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
