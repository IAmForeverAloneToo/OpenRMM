//go:build !windows

package response

import (
	"context"
	"errors"
	"os"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// ErrNotFound reports a registry key that does not exist.
var ErrNotFound = errors.New("not found")

func processList(context.Context, *HashCache, *notes) ([]protocol.ProcessDetail, error) {
	return nil, ErrUnsupported
}
func connections(context.Context, *notes) ([]protocol.Connection, error) { return nil, ErrUnsupported }
func services(context.Context, *HashCache, *notes) ([]protocol.ServiceDetail, error) {
	return nil, ErrUnsupported
}
func tasks(context.Context, *notes) ([]protocol.TaskDetail, error) { return nil, ErrUnsupported }
func persistence(context.Context, *HashCache, *notes) ([]protocol.PersistenceEntry, error) {
	return nil, ErrUnsupported
}
func fileIdentity(*os.File) string { return "" }
func registryKey(string, *notes) (*protocol.RegistryKeyState, error) {
	return nil, ErrUnsupported
}

// huntSourcesFor has no sources off Windows: indicator hunts are unsupported.
func huntSourcesFor(*HashCache, *notes) huntSources { return huntSources{} }
