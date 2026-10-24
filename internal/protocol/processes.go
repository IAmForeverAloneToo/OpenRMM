package protocol

// Start is the exact Windows creation FILETIME, encoded as decimal text to avoid
// loss of precision in JSON clients. An empty value means access was unavailable.
type Process struct {
	PID          uint32  `json:"pid"`
	Start        string  `json:"start"`
	Name         string  `json:"name"`
	CPU          *uint32 `json:"cpu_basis_points"`
	Memory       *uint64 `json:"working_set_bytes"`
	CanTerminate bool    `json:"can_terminate"`
}
type Processes struct {
	Coverage string    `json:"coverage"`
	Items    []Process `json:"items"`
	// Skipped counts processes left out (invalid metadata or over the bounds).
	// Omitted by agents that predate it.
	Skipped int `json:"skipped,omitempty"`
}
type ProcessAction struct {
	ID        string `json:"id"`
	PID       uint32 `json:"pid"`
	Start     string `json:"start"`
	Name      string `json:"name"`
	ExpiresAt int64  `json:"expires_at"`
}
type ProcessDispatch struct {
	Action *ProcessAction `json:"action"`
}
type ProcessResult struct {
	ID      string `json:"id"`
	Outcome string `json:"outcome"`
}
