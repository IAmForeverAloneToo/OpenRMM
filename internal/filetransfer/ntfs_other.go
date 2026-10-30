//go:build !windows

package filetransfer

import "context"

func openNTFS(context.Context, []string, bool, int64, EvidenceOptions) (Evidence, string) {
	return Evidence{}, "denied"
}

func NTFSFiles(context.Context, func(NTFSEntry) bool) ([]string, error) { return nil, nil }
