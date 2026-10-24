package protocol

// Software describes uninstall registrations, not every executable. IDs
// identify a registration within a registry view: "64" and "32" are
// machine-wide; "user" (capability version 2) is a per-user
// registration from the loaded hive of a signed-in user.
type SoftwareEntry struct {
	ID        string `json:"id"`
	View      string `json:"registry_view"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	User      string `json:"user,omitempty"`
	UserSID   string `json:"user_sid,omitempty"`
}

// SoftwareUser is a loaded user hive that was read (version 2).
type SoftwareUser struct {
	SID  string `json:"sid"`
	Name string `json:"name"`
}
type Software struct {
	Coverage string          `json:"coverage"`
	Entries  []SoftwareEntry `json:"entries"`
	// Skipped counts registrations left out (unreadable or invalid metadata, or
	// over the bounds). Omitted by agents that predate it.
	Skipped int `json:"skipped,omitempty"`
	// Users are the signed-in users whose registrations were read (version 2).
	Users []SoftwareUser `json:"users,omitempty"`
	// UserSkipped counts per-user registrations and user hives left out;
	// Skipped then counts machine-wide ones only (version 2).
	UserSkipped int `json:"user_skipped,omitempty"`
}
