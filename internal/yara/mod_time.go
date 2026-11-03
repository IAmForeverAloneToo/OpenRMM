package yara

import "time"

// The time module: now(), the scan's time in seconds since 1970.

func init() {
	register(&module{
		name: "time",
		t: structT(map[string]*ftype{
			"now": funcT(overload("", tInt, func(*evaluator, any, []value) value { return intV(time.Now().Unix()) })),
		}),
		load: func(*evaluator) any { return obj{} },
	})
}
