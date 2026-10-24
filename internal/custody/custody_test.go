package custody

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func chain(t *testing.T, n int) []Record {
	t.Helper()
	out := []Record{}
	prev := Genesis
	for i := 1; i <= n; i++ {
		text, err := Encode(Entry{Version: Version, CaseID: "c1", Sequence: int64(i), At: Stamp(time.Unix(1800000000+int64(i), 0)), Actor: "owner", Action: "note", Details: map[string]string{"text": "step", "b": "1", "a": "2"}, Outcome: "success", PrevHash: prev})
		if err != nil {
			t.Fatal(err)
		}
		r := Record{Entry: text, Hash: Hash(prev, text)}
		out = append(out, r)
		prev = r.Hash
	}
	return out
}

func TestVerifyDetectsTamperingReorderingAndTruncation(t *testing.T) {
	records := chain(t, 4)
	head, err := Verify("c1", records)
	if err != nil || head != records[3].Hash {
		t.Fatal(err)
	}
	if !strings.Contains(records[0].Entry, `"details":{"a":"2","b":"1","text":"step"}`) {
		t.Fatal("details not in sorted order", records[0].Entry)
	}
	altered := append([]Record{}, records...)
	altered[1].Entry = strings.Replace(altered[1].Entry, "step", "STEP", 1)
	removed := append(append([]Record{}, records[:1]...), records[2:]...)
	swapped := []Record{records[1], records[0], records[2], records[3]}
	rehashed := append([]Record{}, records...)
	rehashed[2].Entry = strings.Replace(rehashed[2].Entry, "step", "STEP", 1)
	rehashed[2].Hash = Hash(records[1].Hash, rehashed[2].Entry) // the next entry still names the old hash
	for name, list := range map[string][]Record{"altered": altered, "removed": removed, "swapped": swapped, "rehashed": rehashed} {
		if _, err := Verify("c1", list); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	if _, err := Verify("other", records); err == nil {
		t.Fatal("entries of another case accepted")
	}

	x := Export{Format: Format, Version: Version, ExportedAt: Stamp(time.Now()), Case: Case{ID: "c1"}, Entries: records, Head: head}
	b, _ := json.Marshal(x)
	if _, err := VerifyExport(b); err != nil {
		t.Fatal(err)
	}
	x.Entries = records[:3] // truncated at the end: only the head reveals it
	b, _ = json.Marshal(x)
	if _, err := VerifyExport(b); err == nil {
		t.Fatal("truncated export accepted")
	}
}
