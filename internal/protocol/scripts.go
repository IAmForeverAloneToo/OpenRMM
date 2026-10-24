package protocol

type ScriptParameter struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}
type ScriptDefinition struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Body        string            `json:"body"`
	Parameters  []ScriptParameter `json:"parameters"`
	Timeout     int               `json:"timeout_seconds"`
	RunAs       string            `json:"run_as"`
}
type ScriptVersion struct {
	ID         string           `json:"id"`
	ScriptID   string           `json:"script_id"`
	Number     int              `json:"number"`
	Hash       string           `json:"sha256"`
	Definition ScriptDefinition `json:"definition"`
}
type ScriptJob struct {
	ID        string            `json:"id"`
	Version   ScriptVersion     `json:"version"`
	Arguments map[string]string `json:"arguments"`
	ExpiresAt int64             `json:"expires_at"`
}
type ScriptDispatch struct {
	Job *ScriptJob `json:"job"`
}
type ScriptSupport struct {
	Restricted    bool   `json:"restricted"`
	Administrator string `json:"administrator"`
	// RunnerRevision is the installed SYSTEM script runner's revision (0 when
	// the runner is older than revision reporting or not installed).
	RunnerRevision int `json:"runner_revision,omitempty"`
}
type ScriptResult struct {
	ID        string `json:"id"`
	Outcome   string `json:"outcome"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  *int32 `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}
type ScriptReceipt struct {
	DeviceID   string `json:"device_id"`
	ReceivedAt int64  `json:"received_at"`
	Cancel     bool   `json:"cancel"`
}
