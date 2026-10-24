//go:build !windows

package alerting

import (
	"os"
	"path/filepath"
	"syscall"
)

func privateConfig(path string, f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return ErrMailConfig
	}
	if info.Mode().Perm()&0077 != 0 {
		return ErrMailConfig
	}
	if owner, ok := info.Sys().(*syscall.Stat_t); !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
		return ErrMailConfig
	}
	// Private ancestors prevent replacement of a protected file by another user.
	parent := filepath.Dir(path)
	p, e := os.Stat(parent)
	if e != nil || p.Mode().Perm()&0022 != 0 {
		return ErrMailConfig
	}
	if owner, ok := p.Sys().(*syscall.Stat_t); !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
		return ErrMailConfig
	}
	return nil
}
