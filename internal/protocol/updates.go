package protocol

type UpdateIdentity struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}
type WindowsUpdate struct {
	UpdateIdentity
	Title       string   `json:"title"`
	Description string   `json:"description"`
	KB          []string `json:"kb"`
	Severity    string   `json:"severity"`
	Blocked     string   `json:"blocked"`
}
type UpdateSupport struct {
	Windowed   bool   `json:"windowed_jobs,omitempty"`
	Broker     string `json:"broker"`
	CanInstall bool   `json:"can_install"`
	CanRestart bool   `json:"can_restart"`
}
type UpdateJob struct {
	WindowStart int64            `json:"window_start,omitempty"`
	WindowEnd   int64            `json:"window_end,omitempty"`
	ID          string           `json:"id"`
	Action      string           `json:"action"`
	ScanID      string           `json:"scan_id"`
	Updates     []UpdateIdentity `json:"updates"`
	ExpiresAt   int64            `json:"expires_at"`
}
type UpdateDispatch struct {
	Job *UpdateJob `json:"job"`
}
type UpdateItemResult struct {
	UpdateIdentity
	Outcome string `json:"outcome"`
	HResult uint32 `json:"hresult"`
}
type UpdateProgress struct {
	ID             string          `json:"id"`
	Phase          string          `json:"phase"`
	Outcome        string          `json:"outcome"`
	HResult        uint32          `json:"hresult"`
	Completed      int             `json:"completed"`
	Total          int             `json:"total"`
	RebootKnown    bool            `json:"reboot_known"`
	RebootRequired bool            `json:"reboot_required"`
	Catalog        []WindowsUpdate `json:"catalog"`
	Truncated      bool            `json:"truncated"`
	// Skipped counts scanned updates left out of Catalog because their metadata
	// failed validation. Omitted by agents that predate it.
	Skipped int                `json:"skipped,omitempty"`
	Items   []UpdateItemResult `json:"items"`
}
