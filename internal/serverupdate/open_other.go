//go:build !unix

package serverupdate

import "os"

const openFlags = os.O_RDONLY
