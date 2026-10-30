package protocol

import (
	"slices"
	"strings"
)

// AbilityNTFS is reported in the heartbeat by agents that collect NTFS
// artifacts (evidence source "ntfs").
const AbilityNTFS = "ntfs"

// NTFSFormat names the manifest in an NTFS artifact package.
const NTFSFormat = "openrmm-ntfs"

// NTFSAll asks for every fixed NTFS volume.
const NTFSAll = "all"

// NTFSQuery is the query of an NTFS collection: "" for the system drive,
// "all", or drive letters such as "C:,D:".
func NTFSQuery(all bool, volumes []string) string {
	if all {
		return NTFSAll
	}
	return strings.Join(volumes, ",")
}

// ParseNTFSQuery checks a query and returns its volumes in order, upper
// case and without repeats (nil for the system drive), or all.
func ParseNTFSQuery(q string) (volumes []string, all bool, ok bool) {
	if q == "" {
		return nil, false, true
	}
	if q == NTFSAll {
		return nil, true, true
	}
	for _, v := range strings.Split(q, ",") {
		v = strings.ToUpper(v)
		if len(v) != 2 || v[0] < 'A' || v[0] > 'Z' || v[1] != ':' || slices.Contains(volumes, v) {
			return nil, false, false
		}
		volumes = append(volumes, v)
	}
	slices.Sort(volumes)
	return volumes, false, true
}

// NTFSManifest is manifest.json in an NTFS artifact package. Each volume
// has a folder named after its letter (C/) with the raw $MFT, $LogFile and
// $J (the allocated part of the USN journal) and the parsed mft.csv and
// usn.csv.
type NTFSManifest struct {
	Format     string       `json:"format"`
	Version    int          `json:"version"`
	DeviceTime string       `json:"device_time"`
	Volumes    []NTFSVolume `json:"volumes"`
	Notes      []string     `json:"notes"`
}

// NTFSVolume describes one volume's part of the package.
type NTFSVolume struct {
	Volume      string `json:"volume"`
	Serial      string `json:"serial,omitempty"`
	ClusterSize int    `json:"cluster_size,omitempty"`
	RecordSize  int    `json:"record_size,omitempty"`
	// Method is snapshot (read from a shadow copy) or live.
	Method     string     `json:"method,omitempty"`
	Snapshot   string     `json:"snapshot,omitempty"`
	SnapshotAt int64      `json:"snapshot_at,omitempty"`
	Files      []NTFSFile `json:"files"`
	// JournalOffset is where the copied $J starts in the journal stream
	// (its earlier part is unallocated); usn.csv offsets are in the stream.
	JournalOffset int64 `json:"journal_offset,omitempty"`
	MFTRows       int64 `json:"mft_rows"`
	USNRows       int64 `json:"usn_rows"`
	// Damaged counts records that did not decode; Excluded counts timeline
	// rows left out because they are OpenRMM's own files.
	Damaged  int64  `json:"damaged"`
	Excluded int64  `json:"excluded"`
	Error    string `json:"error,omitempty"`
}

// NTFSFile is one file in a volume's folder.
type NTFSFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
