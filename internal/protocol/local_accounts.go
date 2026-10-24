package protocol

// LocalAccount is a local Windows user account. Times are Unix
// seconds; 0 means never or not provided. Windows maintains LastLogonAt on
// this machine only, so it can miss network and cached logons.
type LocalAccount struct {
	Name                 string `json:"name"`
	FullName             string `json:"full_name"`
	SID                  string `json:"sid"`
	Enabled              bool   `json:"enabled"`
	LockedOut            bool   `json:"locked_out"`
	PasswordLastSetAt    int64  `json:"password_last_set_at"`
	PasswordNeverExpires bool   `json:"password_never_expires"`
	PasswordExpired      bool   `json:"password_expired"`
	LastLogonAt          int64  `json:"last_logon_at"`
}

// GroupMember is a direct member of a privileged local group.
type GroupMember struct {
	Name string `json:"name"` // DOMAIN\name; empty when it cannot be resolved
	SID  string `json:"sid"`
	Kind string `json:"kind"` // user, group, well_known, computer, deleted, other
}

// LocalGroup is a privileged local group, found by its well-known SID so
// localized group names do not matter. Key is administrators or
// remote_desktop_users; Name is the group's name on this machine.
type LocalGroup struct {
	Key     string        `json:"key"`
	Name    string        `json:"name"`
	Members []GroupMember `json:"members"`
	Skipped int           `json:"skipped,omitempty"`
}
type LocalAccounts struct {
	Accounts []LocalAccount `json:"accounts"`
	Groups   []LocalGroup   `json:"groups"`
	// Skipped counts accounts left out (invalid details, or over the bounds).
	Skipped int `json:"skipped,omitempty"`
}
