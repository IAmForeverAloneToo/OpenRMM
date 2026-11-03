package prefetch

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// compressWindows compresses with Windows' own XPRESS Huffman encoder, the
// one that writes compressed prefetch files.
func compressWindows(t *testing.T, data []byte) []byte {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	size, compress := ntdll.NewProc("RtlGetCompressionWorkSpaceSize"), ntdll.NewProc("RtlCompressBuffer")
	const format = 4 | 0x100 // XPRESS Huffman, maximum compression
	var work, fragment uint32
	if r, _, _ := size.Call(format, uintptr(unsafe.Pointer(&work)), uintptr(unsafe.Pointer(&fragment))); r != 0 {
		t.Fatalf("workspace size: %x", r)
	}
	ws := make([]byte, work)
	out := make([]byte, len(data)+len(data)/8+4096)
	var n uint32
	if r, _, _ := compress.Call(format, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), 4096, uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&ws[0]))); r != 0 {
		t.Fatalf("compress: %x", r)
	}
	return out[:n]
}

// Windows' encoder output decodes to the original: text with short and
// long matches (over 18 and over 270 bytes) across several 64 KiB blocks,
// and random bytes.
func TestWindowsCompressor(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	var text bytes.Buffer
	for text.Len() < 300_000 {
		switch r.IntN(4) {
		case 0:
			text.Write(bytes.Repeat([]byte{byte('a' + r.IntN(26))}, 20+r.IntN(2000)))
		case 1:
			text.WriteString(`\VOLUME{01d1a2b3c4d5e6f7-1234abcd}\WINDOWS\SYSTEM32\`)
		default:
			for range 1 + r.IntN(40) {
				text.WriteByte(byte(r.IntN(256)))
			}
		}
	}
	random := make([]byte, 200_000)
	for k := range random {
		random[k] = byte(r.Uint32())
	}
	for _, data := range [][]byte{text.Bytes(), random, []byte("x"), bytes.Repeat([]byte("ab"), 70_000)} {
		got, err := decompressHuffman(compressWindows(t, data), len(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: %v", len(data), err)
		}
	}
	// A whole compressed prefetch file.
	plain := build(30, true)
	pf := append([]byte("MAM\x04"), binary.LittleEndian.AppendUint32(nil, uint32(len(plain)))...)
	pf = append(pf, compressWindows(t, plain)...)
	if i, err := Parse(pf); err != nil || i.Executable != "NOTEPAD.EXE" || i.RunCount != 42 {
		t.Fatal(i, err)
	}
}
