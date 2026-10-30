package filetransfer

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"strings"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/ntfs/ntfstest"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// A volume's folder holds the raw files and both timelines; OpenRMM's own
// files are left out of the timelines.
func TestWriteNTFSVolume(t *testing.T) {
	vol, journal := ntfstest.Volume()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mv := protocol.NTFSVolume{Volume: "C:"}
	if e := writeNTFSVolume(context.Background(), zw, "C:", bytes.NewReader(vol), []string{`C:\$Extend`}, &mv); e != nil {
		t.Fatal(e)
	}
	if e := zw.Close(); e != nil {
		t.Fatal(e)
	}
	names := []string{}
	for _, f := range mv.Files {
		names = append(names, f.Name)
	}
	if strings.Join(names, " ") != "C/$MFT C/$J C/mft.csv C/usn.csv" || mv.JournalOffset != 2*ntfstest.Cluster || mv.Serial != "0000000000001234" {
		t.Fatalf("files %v %+v", names, mv)
	}
	// $Extend and $Extend\$UsnJrnl are excluded; $MFT, the root, Users,
	// a.txt with its hard link and the deleted gone.exe remain.
	if mv.MFTRows != 6 || mv.Excluded != 2 || mv.USNRows != 2 || mv.Damaged != 0 {
		t.Fatalf("counts %+v", mv)
	}
	r, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	read := func(name string) []byte {
		f, e := r.Open(name)
		if e != nil {
			t.Fatal(name, e)
		}
		b, _ := io.ReadAll(f)
		return b
	}
	if !bytes.Equal(read("C/$J"), append(journal, make([]byte, ntfstest.Cluster-len(journal))...)) {
		t.Fatal("raw $J differs")
	}
	if len(read("C/$MFT")) != 32*ntfstest.RecordSize {
		t.Fatal("raw $MFT size")
	}
	rows, e := csv.NewReader(bytes.NewReader(read("C/usn.csv"))).ReadAll()
	if e != nil || len(rows) != 3 || rows[1][0] != "a.txt" || rows[1][6] != `C:\Users` {
		t.Fatal("usn.csv", rows, e)
	}
	mft := string(read("C/mft.csv"))
	if !strings.Contains(mft, `C:\Users,a.txt`) || strings.Contains(mft, "$UsnJrnl") {
		t.Fatal("mft.csv", mft)
	}
	if !ntfsExcluded(`C:\ProgramData\OpenRMM Agent\state\x`, []string{`C:\ProgramData\OpenRMM Agent\`}) || ntfsExcluded(`C:\ProgramData\OpenRMM Agent2`, []string{`C:\ProgramData\OpenRMM Agent`}) || !ntfsExcluded(`D:\x\.openrmm-upload`, nil) {
		t.Fatal("exclusion rules")
	}
}

func TestMFTFiles(t *testing.T) {
	vol, _ := ntfstest.Volume()
	var got []string
	if e := mftFiles(context.Background(), "C:", bytes.NewReader(vol), func(f NTFSEntry) bool { got = append(got, f.Path); return true }); e != nil {
		t.Fatal(e)
	}
	// Files in use only: $MFT, a.txt under both its links and $UsnJrnl
	// (gone.exe is deleted; the root, $Extend and Users are directories).
	if strings.Join(got, " ") != `C:\$MFT C:\Users\a.txt C:\Link to a.txt C:\$Extend\$UsnJrnl` {
		t.Fatal(got)
	}
	n := 0
	mftFiles(context.Background(), "C:", bytes.NewReader(vol), func(NTFSEntry) bool { n++; return false })
	if n != 1 {
		t.Fatal("did not stop")
	}
}
