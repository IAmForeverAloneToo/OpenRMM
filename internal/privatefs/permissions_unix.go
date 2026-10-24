//go:build !windows

package privatefs

// CreateDirectory sets mode 0700 before callers create any files.
func restrictDirectory(string) error { return nil }

// RestrictInstallation is Windows-only.
func RestrictInstallation(string) error { return nil }
