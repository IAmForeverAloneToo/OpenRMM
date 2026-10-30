package protocol

import (
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SystemHives are the machine hives a case can collect; user
// hives are "NTUSER:<user>" or "USRCLASS:<user>", where user is a profile
// folder name or a SID.
var SystemHives = []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"}

var sidPattern = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)

// ValidHive accepts a hive name for an evidence job of source "hive".
func ValidHive(s string) bool {
	for _, h := range SystemHives {
		if s == h {
			return true
		}
	}
	kind, user, ok := strings.Cut(s, ":")
	if !ok || kind != "NTUSER" && kind != "USRCLASS" {
		return false
	}
	return sidPattern.MatchString(user) || profileName(user)
}

func profileName(s string) bool {
	if s == "" || len(s) > 64 || strings.TrimSpace(s) != s || strings.HasSuffix(s, ".") || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune(`\/:<>"|?*`, r) {
			return false
		}
	}
	return utf8.ValidString(s)
}

// ValidStreamName accepts an alternate data stream name as written after
// the file name, without the type (":$DATA").
func ValidStreamName(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || strings.ContainsRune(`\/:<>"|?*`, r) {
			return false
		}
	}
	return true
}

// SplitStream separates "name:stream" or "name:stream:$DATA" (the part of a
// path after its drive) into the file part and the stream name; stream is
// empty when there is none. ok is false for any other use of a colon.
func SplitStream(rest string) (file, stream string, ok bool) {
	file, stream, found := strings.Cut(rest, ":")
	if !found {
		return rest, "", true
	}
	stream = strings.TrimSuffix(stream, ":$DATA")
	return file, stream, ValidStreamName(stream)
}

func evidenceText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func sha256Text(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}

// Valid checks metadata reported by an agent.
func (m EvidenceMeta) Valid() bool {
	switch m.Method {
	case "read", "backup", "shadow_copy", "registry_save", "action", "export", "triage", "ntfs":
	default:
		return false
	}
	if m.Accessed < 0 || m.Changed < 0 || m.SnapshotAt < 0 || !evidenceText(m.Owner, 512) || !evidenceText(m.OwnerSID, 184) || m.OwnerSID != "" && !sidPattern.MatchString(m.OwnerSID) || len(m.Streams) > MaxEvidenceStreams {
		return false
	}
	if m.Method == "shadow_copy" {
		if !evidenceText(m.Snapshot, 64) || m.Snapshot == "" {
			return false
		}
	} else if m.Snapshot != "" || m.SnapshotAt != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range m.Streams {
		key := strings.ToLower(s.Name)
		if !ValidStreamName(s.Name) || seen[key] || s.Size < 0 || s.SHA256 != "" && !sha256Text(s.SHA256) {
			return false
		}
		seen[key] = true
	}
	return true
}
