package yara

import (
	"math"
	"strconv"
)

// The math module: statistics of a range of the scanned data (offset, size)
// or of text, computed as YARA does (entropy, serial correlation and the
// Monte Carlo pi estimate follow the ent tool), and small helpers.

func init() {
	// stat is a statistic over a range or over text.
	stat := func(f func([]byte) value) *ftype {
		return funcT(
			overload("ii", tFlt, func(e *evaluator, _ any, a []value) value {
				if d, ok := e.rangeData(a[0], a[1]); ok {
					return f(d)
				}
				return undefined
			}),
			overload("s", tFlt, func(_ *evaluator, _ any, a []value) value { return f([]byte(a[0].s)) }),
		)
	}
	register(&module{
		name: "math",
		t: structT(map[string]*ftype{
			"MEAN_BYTES":         tFlt,
			"entropy":            stat(entropy),
			"mean":               stat(mean),
			"serial_correlation": stat(serialCorrelation),
			"monte_carlo_pi":     stat(monteCarloPi),
			"deviation": funcT(
				overload("iif", tFlt, func(e *evaluator, _ any, a []value) value {
					if d, ok := e.rangeData(a[0], a[1]); ok {
						return deviation(d, a[2].f)
					}
					return undefined
				}),
				overload("sf", tFlt, func(_ *evaluator, _ any, a []value) value { return deviation([]byte(a[0].s), a[1].f) }),
			),
			"in_range": funcT(overload("fff", tBool, func(_ *evaluator, _ any, a []value) value {
				return boolV(a[1].f <= a[0].f && a[0].f <= a[2].f)
			})),
			"min": funcT(overload("ii", tInt, func(_ *evaluator, _ any, a []value) value { return intV(min(a[0].i, a[1].i)) })),
			"max": funcT(overload("ii", tInt, func(_ *evaluator, _ any, a []value) value { return intV(max(a[0].i, a[1].i)) })),
			"abs": funcT(overload("i", tInt, func(_ *evaluator, _ any, a []value) value {
				if a[0].i < 0 {
					return intV(-a[0].i)
				}
				return a[0]
			})),
			"to_number": funcT(overload("b", tInt, func(_ *evaluator, _ any, a []value) value {
				if a[0].truth() {
					return intV(1)
				}
				return intV(0)
			})),
			"to_string": funcT(
				overload("i", tStr, func(_ *evaluator, _ any, a []value) value { return value{kind: 's', s: strconv.FormatInt(a[0].i, 10)} }),
				overload("ii", tStr, func(_ *evaluator, _ any, a []value) value {
					if b := a[1].i; b == 8 || b == 10 || b == 16 {
						return value{kind: 's', s: strconv.FormatInt(a[0].i, int(b))}
					}
					return undefined
				}),
			),
			// count, percentage and mode over a range, or over all the data.
			"count": funcT(
				overload("iii", tInt, func(e *evaluator, _ any, a []value) value {
					if d, ok := e.rangeData(a[1], a[2]); ok && validByte(a[0]) {
						return intV(histogram(d)[a[0].i])
					}
					return undefined
				}),
				overload("i", tInt, func(e *evaluator, _ any, a []value) value {
					if !validByte(a[0]) {
						return undefined
					}
					return intV(e.histogram()[a[0].i])
				}),
			),
			"percentage": funcT(
				overload("iii", tFlt, func(e *evaluator, _ any, a []value) value {
					if d, ok := e.rangeData(a[1], a[2]); ok && validByte(a[0]) && len(d) > 0 {
						return floatV(float64(histogram(d)[a[0].i]) / float64(len(d)))
					}
					return undefined
				}),
				overload("i", tFlt, func(e *evaluator, _ any, a []value) value {
					h, n := e.histogram(), int64(0)
					for _, c := range h {
						n += c
					}
					if !validByte(a[0]) || n == 0 {
						return undefined
					}
					return floatV(float64(h[a[0].i]) / float64(n))
				}),
			),
			"mode": funcT(
				overload("ii", tInt, func(e *evaluator, _ any, a []value) value {
					if d, ok := e.rangeData(a[0], a[1]); ok && len(d) > 0 {
						return intV(mostCommon(histogram(d)))
					}
					return undefined
				}),
				overload("", tInt, func(e *evaluator, _ any, _ []value) value { return intV(mostCommon(e.histogram())) }),
			),
		}),
		load: func(*evaluator) any { return obj{"MEAN_BYTES": 127.5} },
	})
}

func validByte(v value) bool { return v.kind == 'i' && v.i >= 0 && v.i <= 255 }

func histogram(d []byte) *[256]int64 {
	var h [256]int64
	for _, b := range d {
		h[b]++
	}
	return &h
}

// histogram counts the bytes of all scanned data.
func (e *evaluator) histogram() *[256]int64 {
	var h [256]int64
	for _, b := range e.blocks {
		for _, c := range b.Data {
			h[c]++
		}
	}
	return &h
}

func mostCommon(h *[256]int64) int64 {
	best := 0
	for i, c := range h {
		if c > h[best] {
			best = i
		}
	}
	return int64(best)
}

func entropy(d []byte) value {
	if len(d) == 0 {
		return floatV(0)
	}
	var ent float64
	for _, c := range histogram(d) {
		if c > 0 {
			p := float64(c) / float64(len(d))
			ent -= p * math.Log2(p)
		}
	}
	return floatV(ent)
}

func mean(d []byte) value {
	if len(d) == 0 {
		return undefined
	}
	var sum float64
	for _, b := range d {
		sum += float64(b)
	}
	return floatV(sum / float64(len(d)))
}

func deviation(d []byte, m float64) value {
	if len(d) == 0 {
		return undefined
	}
	var sum float64
	for _, b := range d {
		sum += math.Abs(float64(b) - m)
	}
	return floatV(sum / float64(len(d)))
}

func serialCorrelation(d []byte) value {
	if len(d) == 0 {
		return undefined
	}
	var t1, t2, t3, last float64
	for _, b := range d {
		v := float64(b)
		t1 += last * v
		t2 += v
		t3 += v * v
		last = v
	}
	t1 += last * float64(d[0])
	t2 *= t2
	n := float64(len(d))
	scc := n*t3 - t2
	if scc == 0 {
		return floatV(-100000)
	}
	return floatV((n*t1 - t2) / scc)
}

func monteCarloPi(d []byte) value {
	const monteN = 6
	inCircle := math.Pow(math.Pow(256, monteN/2)-1, 2)
	var group [monteN]float64
	tries, hits := 0, 0
	for i, b := range d {
		group[i%monteN] = float64(b)
		if i%monteN == monteN-1 {
			var x, y float64
			for j := range monteN / 2 {
				x = x*256 + group[j]
				y = y*256 + group[j+monteN/2]
			}
			tries++
			if x*x+y*y <= inCircle {
				hits++
			}
		}
	}
	if tries == 0 {
		return undefined
	}
	pi := 4 * float64(hits) / float64(tries)
	return floatV(math.Abs((pi - math.Pi) / math.Pi))
}
