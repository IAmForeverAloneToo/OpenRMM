//go:build !windows

package desktop

import (
	"context"
	"log/slog"
)

// EnsureCompanions is available on Windows only.
func EnsureCompanions(context.Context, string, *slog.Logger) {}
