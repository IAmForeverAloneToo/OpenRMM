//go:build !windows

package dpapi

import "errors"

var errUnsupported = errors.New("protected local secrets need Windows")

func Protect([]byte, string) ([]byte, error) { return nil, errUnsupported }

func Unprotect([]byte, string) ([]byte, error) { return nil, errUnsupported }
