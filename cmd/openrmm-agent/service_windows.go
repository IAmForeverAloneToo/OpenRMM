package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/agentservice"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
)

func platformService(args []string) (bool, int) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot determine Windows service context")
		return true, 1
	}
	if !isService {
		return false, 0
	}
	// Services use only their explicit SCM arguments, never interactive shell defaults.
	c, configErr := config.LoadAgent(args, func(string) string { return "" })
	if err := agentservice.Dispatch(c, configErr); err != nil {
		return true, 1
	}
	return true, 0
}
