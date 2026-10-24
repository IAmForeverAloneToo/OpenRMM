package desktop

// Display geometry stays in the local companion. It is never supplied by the
// technician or added to the installed agent's wire protocol.
type region struct{ Left, Top, Right, Bottom int }

func (r region) valid() bool {
	return r.Left >= -65536 && r.Top >= -65536 && r.Right <= 65536 && r.Bottom <= 65536 && r.Right > r.Left && r.Bottom > r.Top && r.Right-r.Left <= 65536 && r.Bottom-r.Top <= 65536
}
func (r region) contains(v region) bool {
	return r.valid() && v.valid() && v.Left >= r.Left && v.Top >= r.Top && v.Right <= r.Right && v.Bottom <= r.Bottom
}

type captureProfile struct{ Width, Height, Quality int }

func profile(name string) (captureProfile, bool) {
	switch name {
	case "bandwidth":
		return captureProfile{960, 540, 40}, true
	case "balanced":
		return captureProfile{MaxWidth, MaxHeight, 65}, true
	case "detail":
		return captureProfile{MaxWidth, MaxHeight, 85}, true
	}
	return captureProfile{}, false
}

// Map a received-image coordinate into a selected monitor's physical pixels,
// then into the pixel centre on the Windows virtual desktop. Handles negative
// monitor origins, unequal sizes and one-pixel dimensions without float rounding.
func displayPoint(x, y int, selected, virtual region) (int, int, error) {
	if x < 0 || x > 65535 || y < 0 || y > 65535 || !virtual.contains(selected) || selected.Right-selected.Left > 32768 || selected.Bottom-selected.Top > 32768 {
		return 0, 0, ErrInvalid
	}
	axis := func(v, start, size, origin, total int) int {
		pixel := int64(start-origin) + (int64(v)*int64(size-1)+32767)/65535
		return min(65535, max(0, int((2*pixel+1)*65536/(2*int64(total)))))
	}
	return axis(x, selected.Left, selected.Right-selected.Left, virtual.Left, virtual.Right-virtual.Left), axis(y, selected.Top, selected.Bottom-selected.Top, virtual.Top, virtual.Bottom-virtual.Top), nil
}
