package server

import (
	"os"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts"
)

// The test binary doubles as the server's artefact parsing process.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == artefacts.ChildArg {
		os.Exit(artefacts.ChildMain(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}
