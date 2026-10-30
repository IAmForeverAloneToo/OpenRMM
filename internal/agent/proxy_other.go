//go:build !windows

package agent

// policyProxy and machineProxy have no machine store outside Windows.
func policyProxy() string { return "" }

func machineProxy() systemProxy { return systemProxy{} }
