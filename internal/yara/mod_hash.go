package yara

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash/crc32"
)

// The hash module: digests of a range of the scanned data (offset, size)
// or of text, as lowercase hex; crc32 and checksum32 as integers.

func init() {
	digest := func(sum func([]byte) []byte) *ftype {
		return funcT(
			overload("ii", tStr, func(e *evaluator, _ any, a []value) value {
				if d, ok := e.rangeData(a[0], a[1]); ok {
					return value{kind: 's', s: hex.EncodeToString(sum(d))}
				}
				return undefined
			}),
			overload("s", tStr, func(_ *evaluator, _ any, a []value) value {
				return value{kind: 's', s: hex.EncodeToString(sum([]byte(a[0].s)))}
			}),
		)
	}
	number := func(sum func([]byte) int64) *ftype {
		return funcT(
			overload("ii", tInt, func(e *evaluator, _ any, a []value) value {
				if d, ok := e.rangeData(a[0], a[1]); ok {
					return intV(sum(d))
				}
				return undefined
			}),
			overload("s", tInt, func(_ *evaluator, _ any, a []value) value { return intV(sum([]byte(a[0].s))) }),
		)
	}
	register(&module{
		name: "hash",
		t: structT(map[string]*ftype{
			"md5":    digest(func(d []byte) []byte { s := md5.Sum(d); return s[:] }),
			"sha1":   digest(func(d []byte) []byte { s := sha1.Sum(d); return s[:] }),
			"sha256": digest(func(d []byte) []byte { s := sha256.Sum256(d); return s[:] }),
			"crc32":  number(func(d []byte) int64 { return int64(crc32.ChecksumIEEE(d)) }),
			"checksum32": number(func(d []byte) int64 {
				var s uint32
				for _, b := range d {
					s += uint32(b)
				}
				return int64(s)
			}),
		}),
		load: func(*evaluator) any { return obj{} },
	})
}
