//go:build !windows

package filetransfer

import (
	"context"
	"os"
)

func createdTime(os.FileInfo) int64 { return 0 }

func openTriage(context.Context, string, []string, int64, EvidenceOptions) (Evidence, string) {
	return Evidence{}, "denied"
}
