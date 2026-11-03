package artefacts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
)

// ChildArg makes the server binary run as a parsing process.
const ChildArg = "-parse-artefacts-child"

// Memory limits of a parsing process: the Go heap target, and on Linux
// the address space (which also covers the runtime's own mappings).
const (
	softMemory    = 2 << 30
	addressMemory = 6 << 30
)

// Outcomes of a parse that did not succeed.
const (
	OutcomeOutputLimit = "output_limit"
	OutcomeTimeLimit   = "time_limit"
	OutcomeCrashed     = "crashed"
	OutcomeUnreadable  = "unreadable"
	OutcomeFailed      = "failed"
)

// result is what a parsing process prints.
type result struct {
	Manifest *Manifest `json:"manifest,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`
}

// ChildMain runs a parse in this process: it lowers its own priority and
// limits its memory, reads the request from in and prints the result.
func ChildMain(in io.Reader, out io.Writer) int {
	limitProcess()
	var req Request
	if json.NewDecoder(io.LimitReader(in, 1<<16)).Decode(&req) != nil {
		return 2
	}
	m, e := Parse(context.Background(), req)
	r := result{Manifest: &m}
	switch {
	case errors.Is(e, ErrOutputLimit):
		r = result{Outcome: OutcomeOutputLimit}
	case errors.Is(e, ErrUnreadable):
		r = result{Outcome: OutcomeUnreadable}
	case e != nil:
		r = result{Outcome: OutcomeFailed}
	}
	if json.NewEncoder(out).Encode(r) != nil {
		return 1
	}
	return 0
}

// Run parses in a separate process, the server binary exe started with
// ChildArg, which sees only the request: no environment, database or keys.
// It stops the process when ctx ends. On failure the outcome names why.
func Run(ctx context.Context, exe string, req Request) (Manifest, string) {
	body, e := json.Marshal(req)
	if e != nil {
		return Manifest{}, OutcomeFailed
	}
	cmd := exec.CommandContext(ctx, exe, ChildArg)
	cmd.Env = []string{}
	if runtime.GOOS == "windows" {
		cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot")}
	}
	cmd.Stdin = bytes.NewReader(body)
	var out bytes.Buffer
	cmd.Stdout = &limited{&out, 8 << 20}
	childAttrs(cmd)
	e = cmd.Run()
	switch {
	case ctx.Err() != nil:
		return Manifest{}, OutcomeTimeLimit
	case e != nil:
		return Manifest{}, OutcomeCrashed
	}
	var r result
	if json.Unmarshal(out.Bytes(), &r) != nil || r.Outcome == "" && r.Manifest == nil {
		return Manifest{}, OutcomeCrashed
	}
	if r.Outcome != "" {
		return Manifest{}, r.Outcome
	}
	return *r.Manifest, ""
}

type limited struct {
	w    io.Writer
	left int
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, errors.New("too much output")
	}
	l.left -= len(p)
	return l.w.Write(p)
}
