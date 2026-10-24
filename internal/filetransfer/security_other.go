//go:build !windows

package filetransfer

import (
	"errors"
	"os"
)

func canonical(string) (string, error)       { return "", errors.New("unsupported") }
func canonicalFile(*os.File) (string, error) { return "", errors.New("unsupported") }

func safeRoot(string) bool     { return false }
func singleLink(*os.File) bool { return false }

func linksAllowed(*os.File, string, func(string) bool) bool { return false }
func fixedDrives() []LocalRoot                              { return []LocalRoot{} }
