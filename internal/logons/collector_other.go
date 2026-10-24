//go:build !windows

package logons

import (
	"context"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
)

type native struct{}

func NewReader() Reader { return native{} }

func (native) Read(context.Context, string, int, func(string) bool) error {
	return features.ErrUnsupported
}
