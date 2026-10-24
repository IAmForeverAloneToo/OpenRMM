// Command openrmm-custody verifies a case's chain-of-custody export offline.
// It needs no server, network or credentials.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/custody"
)

const usage = `Usage: openrmm-custody verify FILE

Checks an OpenRMM case custody export (Cases > Export custody log): every entry
belongs to the case, is numbered without gaps, names the previous entry's hash
and matches its own hash, and the last hash equals the recorded head. Exit code
0 means the chain is intact; 1 means it is not or the file is invalid.
`

func main() {
	if len(os.Args) != 3 || os.Args[1] != "verify" {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	f, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open the export file.")
		os.Exit(1)
	}
	b, err := io.ReadAll(io.LimitReader(f, 512<<20))
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot read the export file.")
		os.Exit(1)
	}
	x, err := custody.VerifyExport(b)
	if err != nil {
		fmt.Fprintln(os.Stderr, "NOT VERIFIED:", err)
		os.Exit(1)
	}
	fmt.Printf("Verified: case %s (%q), %d entries, head %s\n", x.Case.ID, x.Case.Title, len(x.Entries), x.Head)
}
