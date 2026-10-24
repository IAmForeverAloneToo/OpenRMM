package desktop

import "testing"

func TestDisplayCoordinatesStayOnSelectedMonitor(t *testing.T) {
	for _, pair := range [][2]region{
		{{-1920, -1080, 3840, 2160}, {-1920, 0, 0, 1080}},
		{{-1920, -1080, 3840, 2160}, {0, -1080, 1920, 0}},
		{{0, 0, 3840, 2160}, {1920, 0, 3840, 2160}},
		{{0, 0, 1, 1}, {0, 0, 1, 1}},
		{{-32768, 0, 32768, 100}, {-32768, 0, 0, 100}},
	} {
		virtual, selected := pair[0], pair[1]
		for _, v := range []int{0, 1, 15000, 32768, 50000, 65535} {
			x, y, e := displayPoint(v, v, selected, virtual)
			if e != nil || x < 0 || x > 65535 || y < 0 || y > 65535 {
				t.Fatal("bad normalized input", e)
			}
			px := virtual.Left + x*(virtual.Right-virtual.Left)/65536
			py := virtual.Top + y*(virtual.Bottom-virtual.Top)/65536
			wantX := selected.Left + (v*(selected.Right-selected.Left-1)+32767)/65535
			wantY := selected.Top + (v*(selected.Bottom-selected.Top-1)+32767)/65535
			if px != wantX || py != wantY {
				t.Fatal("mapped to another pixel/display", pair, v, px, py, wantX, wantY)
			}
		}
	}
	for _, r := range []region{{0, 0, 0, 1}, {-100000, 0, 1, 1}, {0, 0, 40000, 100}} {
		if _, _, e := displayPoint(0, 0, r, region{0, 0, 40000, 100}); e == nil {
			t.Fatal("invalid display accepted")
		}
	}
	if _, _, e := displayPoint(-1, 0, region{0, 0, 100, 100}, region{0, 0, 100, 100}); e == nil {
		t.Fatal("invalid pointer accepted")
	}
}
