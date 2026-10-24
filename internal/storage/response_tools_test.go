package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

// Tools are stored by hash within the quota; scripts and drops are
// completed by the server from the library and the case; the device fetches
// a drop's file only while its job runs.
func TestToolsAndResolvedActions(t *testing.T) {
	ctx := context.Background()
	s, caseID, device, now := evidenceFixture(t)
	tool, e := s.AddTool(ctx, "Autoruns64.exe", "Sysinternals Autoruns", "owner", strings.NewReader("autoruns binary"), -1, now)
	if e != nil || tool.SHA256 != digest([]byte("autoruns binary")) || tool.Size != 15 {
		t.Fatal("add tool", tool, e)
	}
	if _, e = s.AddTool(ctx, `..\evil.exe`, "", "owner", strings.NewReader("x"), -1, now); !errors.Is(e, ErrTool) {
		t.Fatal("bad name accepted", e)
	}
	s.evidenceQuota = 20
	if _, e = s.AddTool(ctx, "big.exe", "", "owner", strings.NewReader(strings.Repeat("x", 10)), -1, now); !errors.Is(e, ErrTool) {
		t.Fatal("quota ignored", e)
	}
	// Content already stored does not count again.
	if _, e = s.AddTool(ctx, "copy.exe", "", "owner", strings.NewReader("autoruns binary"), -1, now); e != nil {
		t.Fatal("same content refused", e)
	}
	s.evidenceQuota = 0

	drop, e := s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "drop", Source: "tool", Ref: tool.ID, Path: `C:\Tools\Autoruns64.exe`})
	if e != nil || drop.Name != "Autoruns64.exe" || drop.SHA256 != tool.SHA256 || drop.Size != 15 {
		t.Fatal("resolve tool drop", drop, e)
	}
	if _, e = s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "drop", Source: "tool", Ref: tool.ID, Path: `C:\Tools\a.exe:stream`}); e == nil {
		t.Fatal("stream destination accepted")
	}
	// A file from the case's evidence can be dropped too.
	if _, e = s.QueueEvidence(ctx, caseID, device, `C:\x\sample.bin`, "owner", now); e != nil {
		t.Fatal(e)
	}
	collected := collect(t, s, device, now, []byte("sample"), &protocol.EvidenceMeta{Method: "read"})
	back, e := s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "drop", Source: "evidence", Ref: collected.ID, Path: `C:\Restore\sample.bin`, Overwrite: true})
	if e != nil || back.Name != "sample.bin" || back.SHA256 != digest([]byte("sample")) || !back.Overwrite {
		t.Fatal("resolve evidence drop", back, e)
	}
	if _, e = s.ResolveAction(ctx, "ffffffffffffffffffffffffffffffff", protocol.ResponseAction{Kind: "drop", Source: "evidence", Ref: collected.ID, Path: `C:\x.bin`}); e == nil {
		t.Fatal("evidence of another case accepted")
	}

	// Ad hoc scripts get a default name and timeout; library scripts their
	// version's definition.
	adhoc, e := s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "script", Script: "Get-Date", Arguments: map[string]string{}})
	if e != nil || adhoc.Name != "Case script" || adhoc.Timeout != 60 || adhoc.Arguments != nil {
		t.Fatal("ad hoc script", adhoc, e)
	}
	if _, ok := scripting.ResponseJob(strings.Repeat("a", 32), adhoc, 1); !ok {
		t.Fatal("ad hoc job invalid")
	}
	v, e := s.CreateScriptVersion(ctx, ScriptVersion{ScriptVersion: protocol.ScriptVersion{ID: strings.Repeat("b", 32), ScriptID: strings.Repeat("c", 32), Definition: protocol.ScriptDefinition{Name: "Triage", Body: "param($Path) Get-Item $Path", Parameters: []protocol.ScriptParameter{{Name: "Path", Required: true}}, Timeout: 120, RunAs: "system"}}, Actor: "owner"}, now)
	if e != nil {
		t.Fatal(e)
	}
	library, e := s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "script", Ref: v.ID, Arguments: map[string]string{"Path": `C:\x`}})
	if e != nil || library.Name != "Triage" || library.Script != v.Definition.Body || library.Timeout != 120 || len(library.Parameters) != 1 {
		t.Fatal("library script", library, e)
	}
	if _, e = s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "script", Ref: v.ID}); e == nil {
		t.Fatal("missing required argument accepted")
	}

	// The device fetches the payload only while its drop job runs.
	id, e := s.QueueAction(ctx, caseID, device, drop, "owner", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.DropPayload(ctx, device, "fp", id, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("payload before dispatch", e)
	}
	if d, _ := s.DispatchEvidence(ctx, device, "fp", now); d.Job == nil || d.Job.ID != id || d.Job.Action.SHA256 != tool.SHA256 {
		t.Fatal("dispatch drop", d)
	}
	f, size, e := s.DropPayload(ctx, device, "fp", id, now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(b, []byte("autoruns binary")) || size != 15 {
		t.Fatal("payload", string(b))
	}
	if _, _, e = s.DropPayload(ctx, device, "wrong", id, now); e == nil {
		t.Fatal("payload for another device")
	}
	if _, _, e = s.DropPayload(ctx, device, "fp", collected.ID, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("payload of a collection", e)
	}
	// A withdrawn tool can no longer be dropped.
	if e = s.WithdrawTool(ctx, tool.ID, "owner", now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.DropPayload(ctx, device, "fp", id, now); !errors.Is(e, ErrEvidence) {
		t.Fatal("withdrawn tool still delivered", e)
	}
	if _, e = s.ResolveAction(ctx, caseID, protocol.ResponseAction{Kind: "drop", Source: "tool", Ref: tool.ID, Path: `C:\Tools\x.exe`}); e == nil {
		t.Fatal("withdrawn tool dropped")
	}
	tools, _ := s.Tools(ctx)
	if len(tools) != 2 || tools[len(tools)-1].WithdrawnAt == nil && tools[0].WithdrawnAt == nil {
		t.Fatalf("tools %+v", tools)
	}
}
