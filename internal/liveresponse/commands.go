// Package liveresponse parses the built-in commands of a live response
// session. Each command maps onto a case response action or collection;
// the server resolves names (tools, scripts, process identities) before it
// queues the job.
package liveresponse

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// Command is a parsed command line.
type Command struct {
	// Verb is the canonical command name.
	Verb string
	// Action is a ready response action (ps, netstat, services, tasks, reg).
	Action *protocol.ResponseAction
	// Source and Path name a collection (get, hive, evtx); Query is the
	// XPath of an evtx export ("" for the whole channel).
	Source, Path, Query string
	// PID and Tree for kill; the server finds the process identity. Start,
	// when given (the result viewer sends it), must match that identity.
	PID   uint32
	Tree  bool
	Start string
	// Tool, Destination and Overwrite for put.
	Tool, Destination string
	Overwrite         bool
	// Script and Arguments for run.
	Script    string
	Arguments map[string]string
	// Indicators, List and Files for hunt: indicators typed on
	// the line, or a saved list's name the server resolves.
	Indicators []protocol.Indicator
	List       string
	Files      bool
}

// ErrUsage carries a message for the person typing.
type ErrUsage struct{ Message string }

func (e ErrUsage) Error() string { return e.Message }

func usage(s string) error { return ErrUsage{s} }

// Help lists the built-in commands.
const Help = `Built-in commands (anything else is typed into the PowerShell console):
  help                              this list
  ps                                process list with command lines, users and image hashes
  kill <pid> [-tree]                end a process (or its tree); run ps first
  netstat                           TCP/UDP connections with owning processes
  services                          services and drivers with binaries and hashes
  tasks                             scheduled tasks
  persistence                       autostart entries with programs, hashes and signatures
  reg query <key>                   read a registry key (HKLM\..., HKU\..., HKCR\...)
  get <path>                        collect a file (path:stream for a stream)
  hive <name>                       collect a hive: SYSTEM, SOFTWARE, SAM, SECURITY,
                                    DEFAULT, NTUSER:<user>, USRCLASS:<user>
  evtx <channel> [<xpath>]          export an event log as .evtx, whole or matching
                                    an XPath such as "*[System[EventID=4624]]"
  triage [<profile>]                collect a triage package (default: Full triage)
  ntfs [<drive> ... | all]          collect $MFT, $LogFile and the USN journal raw, with
                                    parsed timelines (default: the system drive)
  put <tool> <path> [-overwrite]    write a tool from the tool library to the device
  run <script> [Name=Value ...]     run a library script as SYSTEM
  hunt [-files] <indicator ...>     search this device for indicators: hashes, names,
                                    paths, IPs, domain:..., cmd:... (-files also matches
                                    names and paths of every file on fixed drives and
                                    hashes files in common locations; slow)
  hunt [-files] -list <name>        the same with a saved indicator list (Hunting page)
Paths with spaces go in double quotes.`

// split tokenizes a command line: whitespace-separated, double quotes group
// (a doubled "" inside quotes is a literal quote).
func split(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	quoted, any := false, false
	r := []rune(line)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '"' && quoted && i+1 < len(r) && r[i+1] == '"':
			cur.WriteRune('"')
			i++
		case c == '"':
			quoted, any = !quoted, true
		case unicode.IsSpace(c) && !quoted:
			if any || cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
				any = false
			}
		default:
			if unicode.IsControl(c) {
				return nil, usage("Control characters are not allowed.")
			}
			cur.WriteRune(c)
		}
	}
	if quoted {
		return nil, usage("A quote is not closed.")
	}
	if any || cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out, nil
}

// Parse reads one built-in command line.
func Parse(line string) (Command, error) {
	if len(line) > 8192 {
		return Command{}, usage("The command is too long.")
	}
	w, e := split(line)
	if e != nil {
		return Command{}, e
	}
	if len(w) == 0 {
		return Command{}, usage("Type a command; help lists them.")
	}
	verb, args := strings.ToLower(w[0]), w[1:]
	c := Command{Verb: verb}
	simple := map[string]string{"ps": "processes", "netstat": "connections", "services": "services", "tasks": "tasks", "persistence": "persistence"}
	switch verb {
	case "help":
		return c, nil
	case "ps", "netstat", "services", "tasks", "persistence":
		if len(args) != 0 {
			return c, usage(verb + " takes no arguments.")
		}
		c.Action = &protocol.ResponseAction{Kind: simple[verb]}
	case "reg":
		if len(args) != 2 || strings.ToLower(args[0]) != "query" {
			return c, usage(`Usage: reg query <key>, for example reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`)
		}
		key := normalizeKey(args[1])
		if !protocol.ValidRegistryKey(key) {
			return c, usage("The key must start with HKLM, HKU or HKCR.")
		}
		c.Action = &protocol.ResponseAction{Kind: "registry", Key: key}
	case "kill":
		tree := false
		rest := []string{}
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case strings.EqualFold(a, "-tree"):
				tree = true
			case strings.EqualFold(a, "-start"):
				if i+1 >= len(args) || !digits(args[i+1]) {
					return c, usage("-start takes the process start time from ps.")
				}
				c.Start = args[i+1]
				i++
			default:
				rest = append(rest, a)
			}
		}
		if len(rest) != 1 {
			return c, usage("Usage: kill <pid> [-tree]")
		}
		pid, err := strconv.ParseUint(rest[0], 10, 32)
		if err != nil || pid <= 4 {
			return c, usage("The process ID must be a number above 4.")
		}
		c.PID, c.Tree = uint32(pid), tree
	case "get":
		if len(args) != 1 || args[0] == "" {
			return c, usage(`Usage: get <path>, for example get "C:\Users\alice\Downloads\invoice.pdf"`)
		}
		c.Source, c.Path = "file", args[0]
	case "hive":
		if len(args) != 1 {
			return c, usage("Usage: hive <SYSTEM|SOFTWARE|SAM|SECURITY|DEFAULT|NTUSER:<user>|USRCLASS:<user>>")
		}
		name := args[0]
		if kind, user, ok := strings.Cut(name, ":"); ok {
			name = strings.ToUpper(kind) + ":" + user
		} else {
			name = strings.ToUpper(name)
		}
		if !protocol.ValidHive(name) {
			return c, usage("Unknown hive; help lists them.")
		}
		c.Source, c.Path = "hive", name
	case "triage":
		if len(args) > 1 || len(args) == 1 && (args[0] == "" || len(args[0]) > 100) {
			return c, usage(`Usage: triage [<profile>], for example triage or triage "Quick triage"`)
		}
		c.Source, c.Path = "triage", "full"
		if len(args) == 1 {
			c.Path = args[0]
		}
	case "ntfs":
		c.Source, c.Path = "ntfs", "NTFS artifacts"
		if len(args) == 1 && strings.EqualFold(args[0], protocol.NTFSAll) {
			c.Query = protocol.NTFSAll
			break
		}
		volumes, _, ok := protocol.ParseNTFSQuery(protocol.NTFSQuery(false, args))
		if !ok || len(args) > 26 {
			return c, usage("Usage: ntfs [<drive> ...|all], for example ntfs, ntfs D: or ntfs all")
		}
		c.Query = protocol.NTFSQuery(false, volumes)
	case "evtx":
		if len(args) < 1 || len(args) > 2 || !eventlogs.ValidChannel(args[0]) {
			return c, usage(`Usage: evtx <channel> [<xpath>], for example evtx Security "*[System[EventID=4624]]"`)
		}
		c.Source, c.Path = "evtx", args[0]
		if len(args) == 2 {
			if !eventlogs.ValidXPath(args[1]) {
				return c, usage("The XPath must be one predicate of the form *[...].")
			}
			c.Query = args[1]
		}
	case "put":
		rest := []string{}
		for _, a := range args {
			if strings.EqualFold(a, "-overwrite") {
				c.Overwrite = true
			} else {
				rest = append(rest, a)
			}
		}
		if len(rest) != 2 || !protocol.ValidDropPath(rest[1]) {
			return c, usage(`Usage: put <tool> <full destination path> [-overwrite], for example put Autoruns64.exe C:\IR\Autoruns64.exe`)
		}
		c.Tool, c.Destination = rest[0], rest[1]
	case "hunt":
		rest := []string{}
		for i := 0; i < len(args); i++ {
			switch a := args[i]; {
			case strings.EqualFold(a, "-files"):
				c.Files = true
			case strings.EqualFold(a, "-list"):
				if i+1 >= len(args) || args[i+1] == "" || len(args[i+1]) > 100 {
					return c, usage(`-list takes a saved list's name, for example hunt -list "APT29 2026"`)
				}
				c.List = args[i+1]
				i++
			default:
				rest = append(rest, a)
			}
		}
		if c.List != "" && len(rest) > 0 || c.List == "" && len(rest) == 0 {
			return c, usage(`Usage: hunt [-files] <indicator ...> or hunt [-files] -list <name>, for example hunt -files evil.exe 203.0.113.7 domain:bad.example`)
		}
		if c.List == "" {
			list, problems := protocol.ParseIndicators(strings.Join(rest, "\n"))
			if len(problems) > 0 {
				return c, usage("Not an indicator: " + problems[0] + ". Use a hash, a name, a path, an IP address or network, domain:<name> or cmd:<text>.")
			}
			if !(protocol.HuntSpec{Indicators: list}).Valid() {
				return c, usage("Give 1 to 1,000 different indicators.")
			}
			c.Indicators = list
		}
	case "run":
		if len(args) < 1 {
			return c, usage("Usage: run <script> [Name=Value ...]")
		}
		c.Script, c.Arguments = args[0], map[string]string{}
		for _, a := range args[1:] {
			k, v, ok := strings.Cut(a, "=")
			if !ok || k == "" {
				return c, usage("Script arguments are Name=Value.")
			}
			c.Arguments[k] = v
		}
	default:
		return c, errors.New("not a built-in command")
	}
	return c, nil
}

// digits accepts a process start stamp (decimal, at most 20 digits).
func digits(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// normalizeKey accepts the long root names too.
func normalizeKey(k string) string {
	for long, short := range map[string]string{"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_USERS": "HKU", "HKEY_CLASSES_ROOT": "HKCR"} {
		if root, rest, found := strings.Cut(k, `\`); strings.EqualFold(root, long) || strings.EqualFold(root, short) {
			if found {
				return short + `\` + rest
			}
			return short
		}
	}
	return k
}
