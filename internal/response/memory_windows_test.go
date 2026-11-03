package response

import (
	"context"
	"os"
	"testing"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/yara"
)

// The main executable image of a process is read as mapped, and the pe
// module describes it at its addresses (this test program's own image).
func TestProcessImage(t *testing.T) {
	img, err := processImage(context.Background(), uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Data) < 0x1000 || string(img.Data[:2]) != "MZ" || img.Base == 0 {
		t.Fatalf("image at %#x, %d bytes", img.Base, len(img.Data))
	}
	rules, err := yara.Compile(`import "pe"
rule own_image { condition: pe.is_pe and pe.is_64bit() and pe.number_of_sections > 2 and entrypoint > pe.image_base
  and entrypoint < pe.image_base + pe.size_of_image and pe.number_of_imports > 0 and pe.imports("kernel32.dll") > 0 }`)
	if err != nil {
		t.Fatal(err)
	}
	if !rules.Uses("pe") {
		t.Fatal("the rules use pe")
	}
	m, err := rules.ScanTarget(context.Background(), []yara.Block{*img}, -1, yara.Target{Image: img})
	if err != nil || len(m) != 1 {
		t.Fatalf("%v %v", m, err)
	}
}
