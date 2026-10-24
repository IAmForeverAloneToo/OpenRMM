// Package terminal owns ephemeral, administrator-authorized interactive shells.
// OS process creation is separate from session ownership and transport.
package terminal

import (
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"time"
	"unicode/utf8"
)

const MaxChunk = 16 * 1024
const MaxInput = 4096
const MaxPending = 128 * 1024
const MaxWire = 32 * 1024

// replyBudget keeps a reply (request plus inputs, after JSON escaping) under
// the 32 KiB response limit of agents released before that limit was raised.
const replyBudget = MaxWire - 2048
const Columns = 100
const Rows = 30

var ErrInvalid = errors.New("invalid or ended terminal session")
var ErrUnavailable = errors.New("terminal disabled, disconnected or in use")

type Request struct {
	ID       string `json:"id"`
	Actor    string `json:"actor"`
	Identity string `json:"identity"`
	Expires  int64  `json:"expires"`
	// Idle is the idle limit in seconds for a long (recorded) session; 0
	// means the normal limits (2 minutes idle, 15 minutes in total).
	Idle int64 `json:"idle,omitempty"`
}

// Normal and long (recorded) session limits. Long limits are used
// only with agents that report Long.
const (
	NormalIdle     = 2 * time.Minute
	NormalLifetime = 15 * time.Minute
	LongIdle       = 15 * time.Minute
	LongLifetime   = 2 * time.Hour
)

type Input struct {
	Sequence uint64 `json:"sequence"`
	Data     string `json:"data"`
}

func (v Input) Valid() bool {
	return v.Sequence > 0 && v.Sequence <= 1000000 && len(v.Data) > 0 && len(v.Data) <= MaxInput && utf8.ValidString(v.Data)
}

type Exchange struct {
	Peer     string `json:"peer"`
	Identity string `json:"identity"`
	ID       string `json:"id,omitempty"`
	State    string `json:"state,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
	Output   []byte `json:"output,omitempty"`
	// Long reports that the agent accepts long sessions.
	Long bool `json:"long,omitempty"`
}

func (p Exchange) Valid() bool {
	if !protocol.ValidID(p.Peer) || len(p.Identity) == 0 || len(p.Identity) > 184 || !utf8.ValidString(p.Identity) || len(p.Output) > MaxChunk || p.Sequence > 1000000 {
		return false
	}
	if p.ID == "" {
		return p.State == "" && p.Sequence == 0 && len(p.Output) == 0
	}
	return protocol.ValidID(p.ID) && (p.State == "active" || p.State == "ended" || p.State == "failed") && (len(p.Output) == 0 || p.Sequence > 0)
}

type Reply struct {
	Request *Request `json:"request,omitempty"`
	Inputs  []Input  `json:"inputs,omitempty"`
	// Active reports a live response command since the last reply; it
	// counts as input for the idle limit.
	Active bool `json:"active,omitempty"`
}
type View struct {
	Request
	DeviceID      string `json:"device_id"`
	State         string `json:"state"`
	Offset        uint64 `json:"offset"`
	Output        []byte `json:"output,omitempty"`
	InputSequence uint64 `json:"input_sequence"`
	// CaseID is set when the session is recorded to a case.
	CaseID string `json:"case_id,omitempty"`
}
