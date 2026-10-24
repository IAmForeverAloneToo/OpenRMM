package protocol

// Session is one signed-in Windows session as the agent observed it.
// Times are Unix seconds. LogonAt is 0 and IdleSeconds is -1 when Windows
// does not provide the value; a console session has no client name or address.
type Session struct {
	ID            uint32 `json:"session_id"`
	User          string `json:"user"`
	Domain        string `json:"domain"`
	State         string `json:"state"`      // active, disconnected, other
	Connection    string `json:"connection"` // console, rdp, other
	Station       string `json:"station"`
	LogonAt       int64  `json:"logon_at"`
	IdleSeconds   int64  `json:"idle_seconds"`
	ClientName    string `json:"client_name"`
	ClientAddress string `json:"client_address"`
}
type Sessions struct {
	Sessions []Session `json:"sessions"`
	// Skipped counts sessions left out (invalid details, or over the bounds).
	// Sessions without a signed-in user (services, listeners) are not sessions
	// here and are not counted.
	Skipped int `json:"skipped,omitempty"`
}
