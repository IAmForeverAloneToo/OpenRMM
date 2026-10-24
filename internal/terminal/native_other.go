//go:build !windows

package terminal

func Identity() (string, error)   { return "", ErrUnavailable }
func Start(string) (Shell, error) { return nil, ErrUnavailable }
