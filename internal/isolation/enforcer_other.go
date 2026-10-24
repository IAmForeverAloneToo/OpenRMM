//go:build !windows

package isolation

// Isolation is enforced on Windows only; elsewhere it is a dry run.
func newPlatformEnforcer() Enforcer { return &DryRun{} }
