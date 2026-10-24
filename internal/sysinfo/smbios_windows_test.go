package sysinfo

import "testing"

// A synthetic SMBIOS table: type 0 (BIOS), type 1 (system with UUID), a
// structure without strings, and the end marker.
func TestParseSMBIOS(t *testing.T) {
	bios := append([]byte{0, 0x12, 0, 0, 1, 2, 0, 0, 3}, make([]byte, 9)...)
	bios = append(bios, "Vendor\x001.2\x0001/02/2026\x00\x00"...)
	system := []byte{1, 0x1b, 1, 0, 1, 2, 0, 3}
	system = append(system, 0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
	system = append(system, 0, 0, 0)
	system = append(system, "Contoso\x00Box\x00SN-1\x00\x00"...)
	empty := []byte{2, 4, 2, 0, 0, 0}
	end := []byte{127, 4, 3, 0, 0, 0}
	var table []byte
	for _, part := range [][]byte{bios, system, empty, end} {
		table = append(table, part...)
	}
	h := parseSMBIOS(table, 302)
	if h.BIOSVendor != "Vendor" || h.BIOSVersion != "1.2" || h.BIOSDate != "01/02/2026" || h.Manufacturer != "Contoso" || h.Model != "Box" || h.Serial != "SN-1" || h.UUID != "00112233-4455-6677-8899-AABBCCDDEEFF" {
		t.Fatalf("parsed %+v", h)
	}
	if old := parseSMBIOS(table, 205); old.UUID != "33221100-5544-7766-8899-AABBCCDDEEFF" {
		t.Fatal("pre-2.6 UUID byte order", old.UUID)
	}
	if parseSMBIOS([]byte{1, 0xff, 0}, 302) != (parseSMBIOS(nil, 302)) {
		t.Fatal("truncated table")
	}
}
