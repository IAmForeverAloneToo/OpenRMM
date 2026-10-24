package response

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// networkPath reports a path on another computer: a UNC or WebDAV path, the
// device-namespace equivalents, or a drive letter mapped to a network share.
// The agent runs as SYSTEM, so opening such a path would make the computer
// account authenticate to whoever named it (an NTLM relay); the agent never
// hashes or verifies such files.
func networkPath(p string) bool {
	s := strings.ReplaceAll(strings.TrimSpace(p), "/", `\`)
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, `\\?\unc\`), strings.HasPrefix(low, `\??\unc\`), strings.HasPrefix(low, `\device\mup`), strings.HasPrefix(low, `\\.\unc\`):
		return true
	case strings.HasPrefix(s, `\\?\`) || strings.HasPrefix(s, `\??\`) || strings.HasPrefix(s, `\\.\`):
		s = s[4:]
	case strings.HasPrefix(s, `\\`):
		return true
	}
	volume := filepath.VolumeName(s)
	if len(volume) != 2 || volume[1] != ':' {
		return false
	}
	root, e := windows.UTF16PtrFromString(volume + `\`)
	return e != nil || windows.GetDriveType(root) == windows.DRIVE_REMOTE
}
