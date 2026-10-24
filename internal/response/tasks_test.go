package response

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

func utf16File(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := []byte{0xFF, 0xFE}
	for _, v := range u {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	return b
}

// Task definitions are UTF-16 XML as Windows writes them.
func TestParseTask(t *testing.T) {
	x := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>EVIL\mallory</Author><Description>Updater</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger><TimeTrigger><StartBoundary>2026-10-22T10:00:00</StartBoundary><Enabled>false</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>false</Enabled><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\Users\Public\x.exe</Command><Arguments>-q</Arguments></Exec><ComHandler><ClassId>{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}</ClassId></ComHandler></Actions>
</Task>`
	task, e := parseTask(utf16File(x))
	if e != nil {
		t.Fatal(e)
	}
	want := protocol.TaskDetail{Enabled: false, Hidden: true, Author: `EVIL\mallory`, Description: "Updater", UserID: "S-1-5-18", RunLevel: "HighestAvailable", Triggers: []string{"LogonTrigger", "TimeTrigger from 2026-10-22T10:00:00 (disabled)"}, Actions: []protocol.TaskAction{{Command: `C:\Users\Public\x.exe`, Arguments: "-q"}, {ClassID: "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"}}}
	if task.Enabled != want.Enabled || task.Hidden != want.Hidden || task.Author != want.Author || task.UserID != want.UserID || task.RunLevel != want.RunLevel || len(task.Triggers) != 2 || task.Triggers[1] != want.Triggers[1] || len(task.Actions) != 2 || task.Actions[0] != want.Actions[0] || task.Actions[1] != want.Actions[1] {
		t.Fatalf("parsed %+v", task)
	}
	if _, e := parseTask([]byte("not xml")); e == nil {
		t.Fatal("garbage parsed")
	}
}

func TestActionSpecs(t *testing.T) {
	for _, c := range []struct {
		a  protocol.ResponseAction
		ok bool
	}{
		{protocol.ResponseAction{Kind: "processes"}, true}, {protocol.ResponseAction{Kind: "processes", PID: 5}, false},
		{protocol.ResponseAction{Kind: "registry", Key: `HKLM\SOFTWARE\Microsoft`}, true}, {protocol.ResponseAction{Kind: "registry", Key: "HKU"}, true},
		{protocol.ResponseAction{Kind: "registry", Key: `HKCU\Software`}, false}, {protocol.ResponseAction{Kind: "registry", Key: `HKLM\\x`}, false}, {protocol.ResponseAction{Kind: "registry", Key: `HKLM\x\`}, false},
		{protocol.ResponseAction{Kind: "kill", PID: 1234, Start: "133", Name: "x.exe", Tree: true}, true}, {protocol.ResponseAction{Kind: "kill", PID: 4, Start: "1", Name: "System"}, false},
		{protocol.ResponseAction{Kind: "kill", PID: 1234, Start: "0133", Name: "x.exe"}, false}, {protocol.ResponseAction{Kind: "kill", PID: 1234, Start: "1", Name: `..\x.exe`}, false}, {protocol.ResponseAction{Kind: "format"}, false},
	} {
		if c.a.Valid() != c.ok {
			t.Fatal("valid", c.a)
		}
		if c.ok {
			if back, ok := protocol.ParseAction(c.a.Text()); !ok || back.Text() != c.a.Text() {
				t.Fatal("round trip", c.a)
			}
		}
	}
	if _, ok := protocol.ParseAction(`{"kind":"processes","extra":1}`); ok {
		t.Fatal("unknown field accepted")
	}
	if _, ok := protocol.ParseAction(`{"kind": "processes"}`); ok {
		t.Fatal("non-canonical text accepted")
	}
}
