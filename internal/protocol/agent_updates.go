package protocol

type AgentManifest struct {
	Format       int    `json:"format"`
	Product      string `json:"product"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Version      string `json:"version"`
	Sequence     int64  `json:"sequence"`
	Size         int64  `json:"size"`
	Hash         string `json:"sha256"`
	KeyID        string `json:"key_id"`
	Issued       int64  `json:"issued_at"`
	Expires      int64  `json:"expires_at"`
	// Format 2: the artifact is a Windows Installer package and
	// AgentHash is the SHA-256 of the openrmm-agent.exe it installs, which is
	// what devices report as their current hash. Format 1 artifacts are the
	// executable itself and leave both fields empty.
	Package   string `json:"package,omitempty"`
	AgentHash string `json:"agent_sha256,omitempty"`
}
type SignedAgentRelease struct {
	Manifest  AgentManifest `json:"manifest"`
	Signature string        `json:"signature"`
}
type AgentUpgradeJob struct {
	ID           string             `json:"id"`
	Release      SignedAgentRelease `json:"release"`
	PublicKey    string             `json:"public_key"`
	ExpectedHash string             `json:"expected_sha256"`
	ExpiresAt    int64              `json:"expires_at"`
}
type AgentUpgradeResult struct {
	ID       string `json:"id"`
	Outcome  string `json:"outcome"`
	Hash     string `json:"sha256"`
	Sequence int64  `json:"sequence"`
}
type AgentUpgradeSupport struct {
	Broker      string   `json:"broker"`
	CurrentHash string   `json:"current_sha256"`
	HighWater   int64    `json:"high_water"`
	KeyIDs      []string `json:"key_ids"`
	// UpdaterRevision is the installed agent updater's revision (0 when the
	// updater is older than revision reporting).
	UpdaterRevision int `json:"updater_revision,omitempty"`
	// Installer is "msi" when the agent updates itself through Windows
	// Installer packages; empty for the separate executable updater.
	Installer string `json:"installer,omitempty"`
}
type AgentUpgradeDispatch struct {
	Job *AgentUpgradeJob `json:"job"`
}
