package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func session(id uint32) protocol.Session {
	return protocol.Session{ID: id, User: "alice", Domain: "CONTOSO", State: "active", Connection: "rdp", Station: "RDP-Tcp#1", LogonAt: 1800000000, IdleSeconds: 30, ClientName: "LAPTOP", ClientAddress: "192.0.2.10"}
}

func report(t *testing.T, raw string) protocol.FeatureReport {
	t.Helper()
	return protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(raw)}
}

func TestSessionsStrictSchema(t *testing.T) {
	good, _ := json.Marshal(protocol.Sessions{Sessions: []protocol.Session{session(2), session(1)}})
	r, err := Normalize(report(t, string(good)))
	if err != nil {
		t.Fatal(err)
	}
	var v protocol.Sessions
	if json.Unmarshal(r.Data, &v) != nil || v.Sessions[0].ID != 1 {
		t.Fatal("not normalised in session order")
	}
	for name, raw := range map[string]string{
		"missing field": strings.Replace(string(good), `"client_address":"192.0.2.10"`, `"x":1`, 1),
		"null field":    strings.Replace(string(good), `"user":"alice"`, `"user":null`, 1),
		"unknown field": strings.Replace(string(good), `{"sessions"`, `{"device_id":"x","sessions"`, 1),
		"null list":     `{"sessions":null}`,
		"empty user":    strings.Replace(string(good), `"user":"alice"`, `"user":""`, 1),
		"bad state":     strings.Replace(string(good), `"state":"active"`, `"state":"busy"`, 1),
		"bad address":   strings.Replace(string(good), `"192.0.2.10"`, `"not-an-ip"`, 1),
		"control text":  strings.Replace(string(good), `"LAPTOP"`, `"LAP\u0007TOP"`, 1),
		"duplicate id":  strings.Replace(string(good), `"session_id":2`, `"session_id":1`, 1),
		"negative idle": strings.Replace(string(good), `"idle_seconds":30`, `"idle_seconds":-2`, 1),
		"trailing data": string(good) + `{}`,
	} {
		if _, err := Normalize(report(t, raw)); !errors.Is(err, features.ErrReport) {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "failed", Data: good}); err == nil {
		t.Fatal("data accepted on a failed report")
	}
	if r, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "sessions", Version: 2}, Status: "ok", Data: good}); err != nil || r.Status != "unsupported" {
		t.Fatal("newer version not reported as unsupported", err)
	}
	empty, err := Normalize(report(t, `{"sessions":[]}`))
	if err != nil || string(empty.Data) != `{"sessions":[]}` {
		t.Fatal("no signed-in users must be a valid report", err)
	}
}

type fixed struct{ list []protocol.Session }

func (f fixed) Collect(context.Context) (protocol.Sessions, error) {
	return protocol.Sessions{Sessions: f.list}, nil
}

func TestModuleBoundsAndCountsSkipped(t *testing.T) {
	list := []protocol.Session{}
	for i := 0; i < MaxSessions+5; i++ {
		list = append(list, session(uint32(i+1)))
	}
	bad := session(1000)
	bad.User = ""
	list = append(list, bad, session(1))
	b, err := Module{Collector: fixed{list}}.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var v protocol.Sessions
	if json.Unmarshal(b, &v) != nil || len(v.Sessions) != MaxSessions || v.Skipped != 7 || !Valid(v) {
		t.Fatal("bounds", len(v.Sessions), v.Skipped)
	}
}
