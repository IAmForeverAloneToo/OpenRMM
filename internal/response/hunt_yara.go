package response

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// YARA rules in hunts: over the files searched and process memory. A rule
// that matches is reported as an indicator of type "yara" named after the
// rule, with the strings that matched.

// noMemoryScan are processes whose memory is never read: LSASS (reading it
// is what credential theft does, and security products alert on it) and
// security products, which refuse or report it. Names are lower case.
var noMemoryScan = map[string]bool{
	"lsass.exe": true,
	// Microsoft Defender and Defender for Endpoint.
	"msmpeng.exe": true, "mpdefendercoreservice.exe": true, "nissrv.exe": true, "mssense.exe": true, "senseir.exe": true,
	"sensecncproxy.exe": true, "sensendr.exe": true, "sensetvm.exe": true, "mpcopyaccelerator.exe": true,
	// Other common antivirus and EDR products.
	"csfalconservice.exe": true, "csfalconcontainer.exe": true, "sentinelagent.exe": true, "sentinelservicehost.exe": true,
	"sentinelstaticengine.exe": true, "sentinelstaticenginescanner.exe": true, "cb.exe": true, "repmgr.exe": true, "cylancesvc.exe": true,
	"elastic-endpoint.exe": true, "elastic-agent.exe": true, "bdservicehost.exe": true, "vsserv.exe": true, "ekrn.exe": true,
	"avp.exe": true, "sophoshealth.exe": true, "sophosfilescanner.exe": true, "savservice.exe": true, "mcshield.exe": true,
	"ntrtscan.exe": true, "tmccsf.exe": true, "xagt.exe": true, "cyserver.exe": true, "cytray.exe": true, "sysmon.exe": true, "sysmon64.exe": true,
}

// skipMemory reports a process whose memory is not scanned: the agent
// itself (it holds the rules' text), and those in noMemoryScan.
func skipMemory(p protocol.ProcessDetail) bool {
	return p.PID <= 4 || p.PID == uint32(os.Getpid()) || noMemoryScan[strings.ToLower(p.Name)]
}

// yaraHits turns matches into indicators and the strings that matched.
func yaraHits(ms []yara.Match) ([]protocol.Indicator, []string) {
	var inds []protocol.Indicator
	var details []string
	for _, m := range ms {
		inds = append(inds, protocol.Indicator{Type: "yara", Value: m.Rule})
		var parts []string
		for i, s := range m.Strings {
			if i == 8 {
				parts = append(parts, fmt.Sprintf("and %d more", len(m.Strings)-i))
				break
			}
			parts = append(parts, fmt.Sprintf("%s at 0x%x", s.ID, s.Offset))
		}
		detail := "rule " + m.Rule
		if len(m.Tags) > 0 {
			detail += " [" + strings.Join(m.Tags, ", ") + "]"
		}
		if len(parts) > 0 {
			detail += ": " + strings.Join(parts, ", ")
		}
		details = append(details, detail)
	}
	return inds, details
}

// yaraFile scans a file of at most MaxYaraFileBytes, or returns a note
// (too_large, unreadable, network_path).
func yaraFile(ctx context.Context, rules *yara.Rules, path string) ([]yara.Match, string) {
	if networkPath(path) {
		return nil, "network_path"
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, "unreadable"
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() {
		return nil, "unreadable"
	}
	if i.Size() > protocol.MaxYaraFileBytes {
		return nil, "too_large"
	}
	data, e := io.ReadAll(io.LimitReader(f, protocol.MaxYaraFileBytes+1))
	if e != nil || int64(len(data)) > protocol.MaxYaraFileBytes {
		return nil, "unreadable"
	}
	ms, e := rules.Scan(ctx, []yara.Block{{Data: data}}, int64(len(data)))
	if e != nil {
		return nil, "unreadable"
	}
	return ms, ""
}

// memory scans the memory of processes (one, when the spec names a PID)
// with the hunt's rules, reporting matches as process matches. It returns
// how many processes were scanned and skipped.
func (m *matcher) memory(ctx context.Context, src huntSources, spec *protocol.YaraSpec, list []protocol.ProcessDetail, add func(protocol.HuntMatch, []protocol.Indicator) bool) (scanned, skipped int) {
	for _, p := range list {
		if ctx.Err() != nil {
			return
		}
		if spec.PID != 0 && p.PID != spec.PID {
			continue
		}
		if skipMemory(p) {
			skipped++
			continue
		}
		var found []yara.Match
		e := src.memory(ctx, p.PID, func(blocks []yara.Block) error {
			ms, err := m.yara.Scan(ctx, blocks, -1)
			found = append(found, ms...)
			return err
		})
		if e != nil {
			skipped++
			continue
		}
		scanned++
		// A rule matching in several batches is reported once.
		seen := map[string]bool{}
		unique := found[:0]
		for _, f := range found {
			if !seen[f.Rule] {
				seen[f.Rule] = true
				unique = append(unique, f)
			}
		}
		inds, details := yaraHits(unique)
		for i, ind := range inds {
			if !add(protocol.HuntMatch{Area: "process", Path: p.Image, Name: p.Name, PID: p.PID, User: p.User, Command: p.CommandLine, SHA256: p.SHA256, Detail: "memory: " + details[i]}, []protocol.Indicator{ind}) {
				return
			}
		}
	}
	return
}
