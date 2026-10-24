package main

import (
	"context"
	"fmt"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"os"
	"os/signal"
)

func main() {
	// The companion is hidden (no window). --background is what the MSI's Run
	// entry and the agent pass; it stays silent where remote desktop is
	// unavailable, such as remote desktop sessions or elevated accounts.
	background := len(os.Args) == 2 && os.Args[1] == "--background"
	if len(os.Args) != 1 && !background {
		fmt.Fprintln(os.Stderr, "Launch openrmm-desktop as the signed-in, non-elevated Windows user.")
		showError("Launch openrmm-desktop as the signed-in, non-elevated Windows user.")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if e := desktop.RunCompanion(ctx); e != nil {
		fmt.Fprintln(os.Stderr, e)
		if !background {
			showError(e.Error())
		}
		os.Exit(1)
	}
}
