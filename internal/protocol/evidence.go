package protocol

// Evidence collection. The server dispatches a job once; the agent
// opens the file, announces it (EvidenceStart), uploads it in chunks of
// ChunkSize bytes (each with its SHA-256), and finishes with the whole-file
// SHA-256 (EvidenceFinish). The server verifies every chunk and the whole
// file before the evidence is accepted.
type EvidenceJob struct {
	ID string `json:"id"`
	// DeviceID binds the job to one device; the agent refuses a
	// job for another device.
	DeviceID string `json:"device_id"`
	Path     string `json:"path"`
	// Source is empty for a file (Path is a local path, optionally with
	// ":stream" for an alternate data stream), "hive" for a registry hive
	// (Path names it, see ValidHive) or "evtx" for an event log
	// export (Path is the channel, Query the event XPath or empty for the
	// whole channel).
	Source string `json:"source,omitempty"`
	Query  string `json:"query,omitempty"`
	// Action is set for source "action": the agent runs it and
	// uploads its result document; Path is then only a label.
	Action *ResponseAction `json:"action,omitempty"`
	// Resumed is set when the server hands out a job again: an
	// agent that lost its journal must then not run a mutating action again.
	Resumed   bool  `json:"resumed,omitempty"`
	ChunkSize int64 `json:"chunk_size"`
	MaxSize   int64 `json:"max_size"`
	ExpiresAt int64 `json:"expires_at"`
}
type EvidenceDispatch struct {
	Job *EvidenceJob `json:"job"`
}

// EvidenceStart describes the opened file; times are Unix nanoseconds.
type EvidenceStart struct {
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"`
	Created  int64  `json:"created"`
	Resolved string `json:"resolved"`
	// Meta describes how the file was read and what it looked like; older
	// agents send none.
	Meta *EvidenceMeta `json:"meta,omitempty"`
}

// EvidenceMeta: Method is read (normal read), backup (read with the backup
// privilege, bypassing permissions), shadow_copy (read from a temporary
// Volume Shadow Copy because the file was locked), registry_save (a
// loaded hive saved with RegSaveKeyEx), action (the result document of a
// response action) or export (an event log exported with
// EvtExportLog). Times are Unix nanoseconds of the
// live file: Accessed, Changed (the file record's change time) and, in
// EvidenceStart, Modified and Created.
type EvidenceMeta struct {
	Method      string           `json:"method"`
	Accessed    int64            `json:"accessed,omitempty"`
	Changed     int64            `json:"changed,omitempty"`
	Attributes  uint32           `json:"attributes,omitempty"`
	Owner       string           `json:"owner,omitempty"`
	OwnerSID    string           `json:"owner_sid,omitempty"`
	Snapshot    string           `json:"snapshot,omitempty"`
	SnapshotAt  int64            `json:"snapshot_at,omitempty"`
	Streams     []EvidenceStream `json:"streams,omitempty"`
	StreamsMore bool             `json:"streams_more,omitempty"`
}

// EvidenceStream is an alternate data stream of a collected file; SHA256 is
// empty when the stream could not be read.
type EvidenceStream struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Evidence limits shared by agent and server.
const (
	MaxEvidenceStreams = 64
	// Streams up to this size are collected as their own evidence.
	SmallStream = 1 << 20
)

// EvidenceProgress lists the chunks the server already holds, so an agent
// resumes after a lost connection.
type EvidenceProgress struct {
	Received []int64 `json:"received"`
}

// EvidenceFinish ends a job: outcome ok with the whole-file hash, or the
// reason the file could not be collected (denied, not_found, too_large,
// changed, failed).
type EvidenceFinish struct {
	Outcome string `json:"outcome"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}
