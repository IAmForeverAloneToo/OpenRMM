// Package selfprotect names the OpenRMM device components that remote service
// and process management must never stop or terminate. It is the single shared
// definition for those lists and deliberately has no dependencies.
package selfprotect

import "strings"

// services are the Windows services OpenRMM installs. The
// script runner, Windows Update broker and agent updater run inside the agent
// (the updater as an on-demand helper); the desktop companion has no service.
var services = [...]string{
	"OpenRMMAgent", // agent (internal/agentservice.Name)
}

// executables are the base names of the binaries built from cmd/ that run on a
// managed device. Matching is by base name only, so a different program using
// one of these names is also refused; that errs toward not terminating.
var executables = [...]string{
	"openrmm-agent.exe",
	"openrmm-update-helper.exe", // copy of the agent that runs self-updates
	"openrmm-desktop.exe",
}

// Services returns a copy of the protected Windows service names.
func Services() []string { return append([]string(nil), services[:]...) }

// Executables returns a copy of the protected executable base names.
func Executables() []string { return append([]string(nil), executables[:]...) }

// Service reports whether name is a protected OpenRMM service. Windows service
// names are case-insensitive.
func Service(name string) bool {
	for _, s := range services {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// Executable reports whether name is a protected OpenRMM executable base name.
// Windows file names are case-insensitive.
func Executable(name string) bool {
	for _, s := range executables {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}
