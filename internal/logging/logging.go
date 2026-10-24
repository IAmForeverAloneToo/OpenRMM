package logging

import (
	"io"
	"log/slog"
)

// New gives both programs the same structured log format.
func New(output io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level}))
}
