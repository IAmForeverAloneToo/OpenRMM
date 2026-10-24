package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/devtls"
)

func run() int {
	f := flag.NewFlagSet("openrmm-devcert", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	output := f.String("out", ".local/tls", "new certificate directory")
	if err := f.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Println("Usage: openrmm-devcert [-out NEW_DIRECTORY]\nDefault: .local/tls. Existing directories are never overwritten. No system trust changes.")
			return 0
		}
		fmt.Fprintln(os.Stderr, "invalid certificate helper arguments; use -help")
		return 2
	}
	if f.NArg() != 0 || *output == "" {
		fmt.Fprintln(os.Stderr, "provide a new output directory with -out; positional arguments are not accepted")
		return 2
	}
	if err := devtls.Generate(*output); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	fmt.Println("Development certificates created; valid for localhost and loopback IPs. Server certificate expires in 7 days. No system trust changes.")
	return 0
}

func main() { os.Exit(run()) }
