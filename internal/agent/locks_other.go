//go:build !windows

package agent

// policyLocks has no machine policy store outside Windows.
func policyLocks() map[string]bool { return map[string]bool{} }
