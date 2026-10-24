package protocol

// Logons is one batch of successful logons from the Windows Security log
// (event 4624), oldest first. The agent sends each logon once,
// after its cursor; More is set when the log holds further logons for the
// next collection.
type Logons struct {
	Logons []Logon `json:"logons"`
	More   bool    `json:"more"`
}

// Logon is one successful interactive, remote or network logon.
type Logon struct {
	RecordID uint64 `json:"record_id"`
	Time     int64  `json:"time"`
	User     string `json:"user"`
	Domain   string `json:"domain"`
	SID      string `json:"sid"`
	// Type is interactive (2), network (3), network_cleartext (8), remote
	// (10, Remote Desktop) or cached (11, cached interactive credentials).
	Type         string `json:"type"`
	SourceIP     string `json:"source_ip"`
	SourcePort   int    `json:"source_port"`
	Workstation  string `json:"workstation"`
	AuthPackage  string `json:"auth_package"`
	LogonProcess string `json:"logon_process"`
	LogonID      string `json:"logon_id"`
	Elevated     bool   `json:"elevated"`
}
