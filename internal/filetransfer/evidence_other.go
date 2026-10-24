//go:build !windows

package filetransfer

import (
	"errors"
	"os"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

var errUnsupported = errors.New("unsupported")

func openBackup(string) (*os.File, error)                 { return nil, errUnsupported }
func openAttributes(string) (*os.File, error)             { return nil, errUnsupported }
func openSnapshotFile(string) (*os.File, error)           { return nil, errUnsupported }
func openStream(string) (*os.File, bool, error)           { return nil, false, errUnsupported }
func fileIndex(*os.File) uint64                           { return 0 }
func sameFile(*os.File, *os.File) bool                    { return false }
func inSnapshot(*os.File, string, string) bool            { return false }
func isLocked(error) bool                                 { return false }
func fileMeta(*os.File) protocol.EvidenceMeta             { return protocol.EvidenceMeta{} }
func deleteShadow(string, string) error                   { return errUnsupported }
func openHive(string, EvidenceOptions) (Evidence, string) { return Evidence{}, "denied" }
func openEventLog(string, string, EvidenceOptions) (Evidence, string) {
	return Evidence{}, "denied"
}

func listStreams(*os.File, string) ([]protocol.EvidenceStream, bool) { return nil, false }

type shadow struct {
	ID, Device string
	At         time.Time
}

func createShadow(string, string) (shadow, error) { return shadow{}, errUnsupported }

// CleanupShadows deletes shadow copies a previous run left behind.
func CleanupShadows(string) {}
