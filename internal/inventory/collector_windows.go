package inventory

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"golang.org/x/sys/windows"
)

type nativeCollector struct{ version string }

func NewCollector(agentVersion string) Collector { return nativeCollector{version: agentVersion} }
func (c nativeCollector) Collect(ctx context.Context) (protocol.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Inventory{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return protocol.Inventory{}, err
	}
	version := windows.RtlGetVersion()
	return protocol.Inventory{Hostname: hostname, OS: "windows", OSVersion: fmt.Sprintf("%d.%d", version.MajorVersion, version.MinorVersion), OSBuild: version.BuildNumber, Architecture: runtime.GOARCH, AgentVersion: c.version}, ctx.Err()
}
