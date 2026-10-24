package filetransfer

import (
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
)

func TestPathsAndTransferContracts(t *testing.T) {
	for _, p := range []string{"../x", "/x", `C:\x`, `\\server\share`, "a//b", "a/./b", "a/../b", "a:stream", "NUL.txt", "COM1", "lpt9.log", "a.", "a ", ".env", "x/.ssh/key", "x/.aws/config", "x/.git/config", ".openrmm-staged", "a\x00b"} {
		if Path(p) {
			t.Errorf("unsafe path %q", p)
		}
	}
	for _, p := range []string{".", "a.txt", "subdir/日本語.bin", "a b/data"} {
		if !Path(p) {
			t.Errorf("valid path rejected %q", p)
		}
	}
	q := protocol.FileJob{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Operation: "upload", Root: "support", Path: "data", Data: []byte("test"), Size: 4, Hash: Digest([]byte("test")), ExpiresAt: 1}
	if !JobValid(q) {
		t.Fatal("valid upload")
	}
	q.Data[0] = 'x'
	if JobValid(q) {
		t.Fatal("digest mismatch")
	}
	q.Operation = "download"
	r := protocol.FileResult{ID: q.ID, Outcome: "succeeded", Data: []byte("good"), Size: 4, Hash: Digest([]byte("good"))}
	if !ResultValid(q, r) {
		t.Fatal("valid download")
	}
	r.Data[0] = 'x'
	if ResultValid(q, r) {
		t.Fatal("false checksum")
	}
	r = protocol.FileResult{ID: q.ID, Outcome: "denied", Data: []byte("secret")}
	if ResultValid(q, r) {
		t.Fatal("failure leaks payload")
	}
}
