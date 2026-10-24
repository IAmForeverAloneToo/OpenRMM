package response

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"strings"
	"unicode/utf16"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Scheduled tasks are read from their XML definitions under
// %SystemRoot%\System32\Tasks (readable by SYSTEM), so no COM is needed.

type taskXML struct {
	Registration struct {
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal []struct {
			UserID   string `xml:"UserId"`
			GroupID  string `xml:"GroupId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Enabled *bool `xml:"Enabled"`
		Hidden  bool  `xml:"Hidden"`
	} `xml:"Settings"`
	Triggers struct {
		Any []struct {
			XMLName       xml.Name
			StartBoundary string `xml:"StartBoundary"`
			Enabled       *bool  `xml:"Enabled"`
		} `xml:",any"`
	} `xml:"Triggers"`
	Actions struct {
		Exec []struct {
			Command    string `xml:"Command"`
			Arguments  string `xml:"Arguments"`
			WorkingDir string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
		COM []struct {
			ClassID string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

// decodeTaskText turns a task file (UTF-16 with a byte order mark, as Windows
// writes them, or UTF-8) into UTF-8 XML without its encoding declaration.
func decodeTaskText(b []byte) ([]byte, error) {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE, len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		var order binary.ByteOrder = binary.LittleEndian
		if b[0] == 0xFE {
			order = binary.BigEndian
		}
		b = b[2:]
		if len(b)%2 != 0 {
			return nil, errors.New("odd UTF-16 length")
		}
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = order.Uint16(b[2*i:])
		}
		b = []byte(string(utf16.Decode(u)))
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		b = b[3:]
	}
	// The declaration still names UTF-16; the text is UTF-8 now.
	if i := bytes.Index(b, []byte("?>")); bytes.HasPrefix(bytes.TrimSpace(b), []byte("<?xml")) && i >= 0 {
		b = b[i+2:]
	}
	return b, nil
}

// parseTask reads one task definition into a TaskDetail (path and file
// facts are filled in by the caller).
func parseTask(raw []byte) (protocol.TaskDetail, error) {
	var t protocol.TaskDetail
	b, e := decodeTaskText(raw)
	if e != nil {
		return t, e
	}
	var x taskXML
	if e = xml.Unmarshal(b, &x); e != nil {
		return t, e
	}
	t.Enabled = x.Settings.Enabled == nil || *x.Settings.Enabled
	t.Hidden = x.Settings.Hidden
	t.Author = clip(x.Registration.Author, 512)
	t.Description = clip(x.Registration.Description, 1024)
	if len(x.Principals.Principal) > 0 {
		p := x.Principals.Principal[0]
		t.UserID = clip(p.UserID, 256)
		if t.UserID == "" {
			t.UserID = clip(p.GroupID, 256)
		}
		t.RunLevel = clip(p.RunLevel, 64)
	}
	for _, v := range x.Triggers.Any {
		if len(t.Triggers) == 32 {
			break
		}
		s := v.XMLName.Local
		if v.StartBoundary != "" {
			s += " from " + clip(v.StartBoundary, 64)
		}
		if v.Enabled != nil && !*v.Enabled {
			s += " (disabled)"
		}
		t.Triggers = append(t.Triggers, s)
	}
	for _, v := range x.Actions.Exec {
		if len(t.Actions) < 32 {
			t.Actions = append(t.Actions, protocol.TaskAction{Command: clip(v.Command, 1024), Arguments: clip(v.Arguments, 4096), WorkingDir: clip(v.WorkingDir, 1024)})
		}
	}
	for _, v := range x.Actions.COM {
		if len(t.Actions) < 32 {
			t.Actions = append(t.Actions, protocol.TaskAction{ClassID: clip(v.ClassID, 64)})
		}
	}
	return t, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
