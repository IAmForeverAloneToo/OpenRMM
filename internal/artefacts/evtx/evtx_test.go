package evtx

import (
	"bytes"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/artefacts/evtx/evtxtest"
)

func TestScan(t *testing.T) {
	b := evtxtest.Log("alice", "bob")
	var got []Event
	st, err := Scan(bytes.NewReader(b), int64(len(b)), func(e Event) error { got = append(got, e); return nil })
	if err != nil || st.Records != 2 || st.BadRecords != 0 || len(got) != 2 {
		t.Fatal(st, err)
	}
	e := got[1]
	s := e.System
	if e.RecordID != 2 || s["Provider"] != "Microsoft-Windows-Security-Auditing" || s["EventID"] != "4672" || s["Level"] != "0" || s["Channel"] != "Security" || s["Computer"] != "PC-1" ||
		s["TimeCreated"] != "2026-11-03 09:30:00.0000000" || s["EventRecordID"] != "2" || s["UserID"] != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("%+v", s)
	}
	if len(e.Data) != 2 || e.Data[0] != (Field{"TargetUserName", "bob"}) || e.Data[1] != (Field{"LogonType", "10"}) {
		t.Fatalf("%+v", e.Data)
	}
}

// Damaged logs never panic.
func TestDamagedLog(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	good := evtxtest.Log("alice", "bob", "carol")
	for range 3000 {
		b := append([]byte(nil), good...)
		for range 1 + r.IntN(20) {
			b[headerSize+r.IntN(2048)] = byte(r.Uint32())
		}
		_, _ = Scan(bytes.NewReader(b), int64(len(b)), func(Event) error { return nil })
	}
}

// A real log, exported locally (wevtutil epl Application app.evtx): set
// OPENRMM_TEST_EVTX to its path. Such logs name the machine, so none is
// kept with the source.
func TestRealLog(t *testing.T) {
	path := os.Getenv("OPENRMM_TEST_EVTX")
	if path == "" {
		t.Skip("set OPENRMM_TEST_EVTX to an exported .evtx file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, withData := 0, 0
	ids := map[string]int{}
	st, err := Scan(bytes.NewReader(b), int64(len(b)), func(e Event) error {
		n++
		ids[e.System["EventID"]]++
		if len(e.Data) > 0 {
			withData++
		}
		if n <= 3 {
			t.Logf("%d %v %v", e.RecordID, e.System, e.Data)
		}
		if e.System["TimeCreated"] == "" || e.System["Provider"] == "" || e.System["EventID"] == "" {
			t.Errorf("record %d incomplete: %v", e.RecordID, e.System)
		}
		return nil
	})
	t.Logf("%+v; %d events, %d with data, %d event IDs", st, n, withData, len(ids))
	if err != nil || n == 0 || st.BadRecords > st.Records/100 {
		t.Fatal(st, err)
	}
}
