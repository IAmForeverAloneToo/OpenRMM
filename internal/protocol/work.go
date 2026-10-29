package protocol

import "slices"

// Work kinds an agent waits for. Instead of each worker asking the server
// every few seconds, the agent holds one request open (WorkWait) naming the
// kinds whose workers are idle; the server answers when it has work for any
// of them, or after WorkWaitSeconds.
const (
	WorkFiles     = "files"
	WorkScripts   = "scripts"
	WorkProcesses = "processes"
	WorkServices  = "services"
	WorkEvents    = "events"
	WorkUpdates   = "updates"
	WorkUpgrades  = "upgrades"
	// WorkTerminal and WorkDesktop also keep the device available for new
	// sessions while the agent waits.
	WorkTerminal = "terminal"
	WorkDesktop  = "desktop"
)

var WorkKinds = []string{WorkFiles, WorkScripts, WorkProcesses, WorkServices, WorkEvents, WorkUpdates, WorkUpgrades, WorkTerminal, WorkDesktop}

// WorkWaitSeconds is how long the server holds a wait without work.
const WorkWaitSeconds = 25

type WorkWait struct {
	Idle []string `json:"idle"`
}

type WorkReply struct {
	Work []string `json:"work"`
}

func (w WorkWait) Valid() bool {
	if len(w.Idle) > len(WorkKinds) {
		return false
	}
	for i, k := range w.Idle {
		if !slices.Contains(WorkKinds, k) || slices.Contains(w.Idle[:i], k) {
			return false
		}
	}
	return true
}
