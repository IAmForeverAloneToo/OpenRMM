//go:build !windows

package filetransfer

import "context"

func openNTFS(context.Context, []string, bool, int64, EvidenceOptions) (Evidence, string) {
	return Evidence{}, "denied"
}
