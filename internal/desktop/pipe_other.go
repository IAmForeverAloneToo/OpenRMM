//go:build !windows

package desktop

import "context"

func ServePipe(context.Context, func(context.Context, Exchange) (Reply, error)) error {
	return ErrUnavailable
}
func RunCompanion(context.Context) error { return ErrUnavailable }
