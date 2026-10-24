// Package protocol defines the small versioned messages shared by server and agent.
package protocol

import (
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Enrollment struct {
	Token        string `json:"token"`
	CSR          string `json:"csr"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
}

type Credential struct {
	DeviceID    string `json:"device_id"`
	Certificate string `json:"certificate"`
	DeviceCA    string `json:"device_ca"`
}

// EnrollmentFile is enrollment.json in a downloaded installer.
// install.ps1 places it in the agent's data folder; the service enrolls with
// it on first start and then deletes it. ServerCA is the PEM trust root for
// both origins; empty means the operating system's trusted roots.
type EnrollmentFile struct {
	Version   int    `json:"version"`
	ServerURL string `json:"server_url"`
	DeviceURL string `json:"device_url"`
	ServerCA  string `json:"server_ca"`
	Token     string `json:"token"`
}

// HTTPSOrigin returns the bare "https://host[:port]" form of value, or false
// when it is not an HTTPS origin without credentials, path, query or fragment.
func HTTPSOrigin(value string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path != "" && u.Path != "/" || len(value) > 253 {
		return "", false
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", false
		}
	}
	return "https://" + u.Host, true
}

type Renewal struct {
	CSR string `json:"csr"`
}
type Identity struct {
	DeviceID string `json:"device_id"`
}

func ValidID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && value == strings.ToLower(value)
}

func ValidMetadata(hostname, platform, architecture string) bool {
	if hostname == "" || len(hostname) > 253 || !utf8.ValidString(hostname) || strings.TrimSpace(hostname) != hostname {
		return false
	}
	for _, character := range hostname {
		if !unicode.IsGraphic(character) {
			return false
		}
	}
	// Add platform adapters and their tested identifiers as OS support expands.
	return platform == "windows" && architecture == "amd64"
}
