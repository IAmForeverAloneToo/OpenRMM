package protocol

import "encoding/json"

type Capability struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Reports carry no claimed device identity or receipt timestamp.
type FeatureReport struct {
	Capability Capability      `json:"capability"`
	Status     string          `json:"status"`
	Data       json.RawMessage `json:"data,omitempty"`
}

type Inventory struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	OSBuild      uint32 `json:"os_build"`
	Architecture string `json:"architecture"`
	AgentVersion string `json:"agent_version"`
}

type DiskSpace struct {
	Drive          string `json:"drive"`
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type CPU struct {
	UsagePercent       float64 `json:"usage_percent"`
	SampleMilliseconds uint32  `json:"sample_ms"`
}

type Uptime struct {
	UptimeSeconds   uint64 `json:"uptime_seconds"`
	EstimatedBootAt int64  `json:"estimated_boot_at"`
}
