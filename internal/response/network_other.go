//go:build !windows

package response

func networkPath(string) bool { return false }
