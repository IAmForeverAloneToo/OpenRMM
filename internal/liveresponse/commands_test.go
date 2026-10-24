package liveresponse

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		line string
		ok   bool
		test func(Command) bool
	}{
		{"help", true, func(c Command) bool { return c.Verb == "help" }},
		{"PS", true, func(c Command) bool { return c.Action != nil && c.Action.Kind == "processes" }},
		{"netstat", true, func(c Command) bool { return c.Action.Kind == "connections" }},
		{"persistence", true, func(c Command) bool { return c.Action.Kind == "persistence" }},
		{"ps -x", false, nil},
		{`hunt -files evil.exe 203.0.113.7 domain:bad.example "C:\Users\*\AppData\x.dll"`, true, func(c Command) bool {
			return c.Files && c.List == "" && len(c.Indicators) == 4 && c.Indicators[1].Type == "ip" && c.Indicators[2].Type == "domain" && c.Indicators[3].Type == "path"
		}},
		{`hunt -list "APT 1"`, true, func(c Command) bool { return c.List == "APT 1" && !c.Files && c.Indicators == nil }},
		{"hunt", false, nil},
		{"hunt -list x evil.exe", false, nil},
		{"hunt domain:*.com", false, nil},
		{`reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`, true, func(c Command) bool {
			return c.Action.Key == `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
		}},
		{`reg query "HKLM\x\Run "`, true, func(c Command) bool { return c.Action.Key == `HKLM\x\Run ` }},
		{`reg query HKCU\Software`, false, nil},
		{"kill 1234 -tree", true, func(c Command) bool { return c.PID == 1234 && c.Tree }},
		{"kill 4", false, nil},
		{"kill 1234 -start 134371488739067439 -tree", true, func(c Command) bool { return c.PID == 1234 && c.Tree && c.Start == "134371488739067439" }},
		{"kill 1234 -start", false, nil},
		{"kill 1234 -start x1", false, nil},
		{`get ""`, false, nil},
		{"kill abc", false, nil},
		{`get "C:\Users\a b\file.txt"`, true, func(c Command) bool { return c.Source == "file" && c.Path == `C:\Users\a b\file.txt` }},
		{`get C:\x`, true, func(c Command) bool { return c.Path == `C:\x` }},
		{`get "C:\x`, false, nil},
		{"hive system", true, func(c Command) bool { return c.Source == "hive" && c.Path == "SYSTEM" }},
		{"hive ntuser:alice", true, func(c Command) bool { return c.Path == "NTUSER:alice" }},
		{"hive HARDWARE", false, nil},
		{`evtx "Microsoft-Windows-PowerShell/Operational"`, true, func(c Command) bool {
			return c.Source == "evtx" && c.Path == "Microsoft-Windows-PowerShell/Operational" && c.Query == ""
		}},
		{`evtx Security "*[System[EventID=4624]]"`, true, func(c Command) bool { return c.Query == "*[System[EventID=4624]]" }},
		{`evtx Security "*[System] or *[System]"`, false, nil},
		{"triage", true, func(c Command) bool { return c.Source == "triage" && c.Path == "full" }},
		{`triage "Quick triage"`, true, func(c Command) bool { return c.Path == "Quick triage" }},
		{"triage a b", false, nil},
		{`evtx C:\Windows\System32\winevt\Logs\Security.evtx`, false, nil},
		{`put Autoruns64.exe "C:\IR Tools\Autoruns64.exe" -overwrite`, true, func(c Command) bool {
			return c.Tool == "Autoruns64.exe" && c.Destination == `C:\IR Tools\Autoruns64.exe` && c.Overwrite
		}},
		{`put tool relative.exe`, false, nil},
		{`run Triage Path="C:\a b" Depth=2`, true, func(c Command) bool {
			return c.Script == "Triage" && c.Arguments["Path"] == `C:\a b` && c.Arguments["Depth"] == "2"
		}},
		{`run Triage oops`, false, nil},
	} {
		got, e := Parse(c.line)
		if (e == nil) != c.ok {
			t.Fatalf("%q: %v", c.line, e)
		}
		if c.ok && !c.test(got) {
			t.Fatalf("%q parsed as %+v", c.line, got)
		}
		var u ErrUsage
		if !c.ok && !errors.As(e, &u) {
			t.Fatalf("%q: error without usage message: %v", c.line, e)
		}
	}
}
