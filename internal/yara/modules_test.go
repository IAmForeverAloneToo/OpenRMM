package yara

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
)

// loads counts how often the test module built its data.
var loads atomic.Int32

// A module for the tests only: a structure with an array of structures, a
// dictionary, a function taking a regular expression, and a decimal.
func init() {
	item := structT(map[string]*ftype{"name": tStr, "size": tInt})
	register(&module{
		name: "tests",
		t: structT(map[string]*ftype{
			"items":   arrayT(item),
			"map":     dictT(tInt),
			"ratio":   tFlt,
			"missing": tInt,
			"has": funcT(overload("r", tBool, func(_ *evaluator, self any, a []value) value {
				for _, it := range self.(obj)["items"].(arr) {
					if regexMatch(a[0], it.(obj)["name"].(string)) {
						return boolV(true)
					}
				}
				return boolV(false)
			})),
		}),
		load: func(*evaluator) any {
			loads.Add(1)
			return obj{
				"items": arr{obj{"name": "alpha", "size": int64(1)}, obj{"name": "beta", "size": int64(20)}},
				"map":   dict{"x": int64(2), "y": int64(3)},
				"ratio": 0.75,
			}
		},
	})
}

func scanText(t *testing.T, src, data string) []string {
	t.Helper()
	rs, err := Compile(src)
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	m, err := rs.Scan(context.Background(), []Block{{Data: []byte(data)}}, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range m {
		names = append(names, x.Rule)
	}
	return names
}

func TestModuleFramework(t *testing.T) {
	loads.Store(0)
	got := scanText(t, `import "tests"
rule field { condition: tests.items[1].name == "beta" and tests.items[0].size == 1 }
rule loop { condition: for any it in tests.items : ( it.size > 10 and it.name startswith "b" ) }
rule all_loop { condition: for all it in tests.items : ( it.size > 10 ) }
rule dict_loop { condition: for any k, v in tests.map : ( k == "y" and v == 3 ) }
rule dict_index { condition: tests.map["x"] == 2 and not defined tests.map["z"] }
rule regex_arg { condition: tests.has(/^al/) and not tests.has(/zeta/) }
rule decimal { condition: tests.ratio * 4 == 3 and tests.ratio > 0.5 and 3.0 \ 2 == 1.5 and 3 \ 2 == 1 }
rule undef { condition: not defined tests.missing and not defined tests.items[5].name }
`, "data")
	if strings.Join(got, ",") != "field,loop,dict_loop,dict_index,regex_arg,decimal,undef" {
		t.Fatal(got)
	}
	if loads.Load() != 1 {
		t.Fatal("module data built", loads.Load(), "times")
	}
	// A rule that never reaches the module does not build its data.
	loads.Store(0)
	scanText(t, `import "tests" rule r { condition: true }`, "x")
	if loads.Load() != 0 {
		t.Fatal("module data built without use")
	}
}

func TestHashMathTime(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	got := scanText(t, `import "hash" import "math" import "time"
rule md5 { condition: hash.md5(0, filesize) == "e2fc714c4727ee9395f324cd2e7f331f" and hash.md5("abcd") == hash.md5(0, 4) }
rule sha { condition: hash.sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d" and hash.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" }
rule crc { condition: hash.crc32("abc") == 0x352441c2 and hash.checksum32("abc") == 294 }
rule out_of_range { condition: not defined hash.md5(2, 10) }
rule stats { condition: math.entropy("aaaa") == 0 and math.mean("\x00\xff") == 127.5 and math.deviation("\x00\xff", math.MEAN_BYTES) == 127.5 }
rule helpers { condition: math.in_range(2, 1.5, 2.5) and math.abs(-3) == 3 and math.min(2, 5) == 2 and math.max(2, 5) == 5 and math.to_number(1 == 1) == 1 and math.to_string(255, 16) == "ff" and math.to_string(-7) == "-7" }
rule counts { condition: math.count(0x61, 0, 4) == 1 and math.count(0x64) == 1 and math.percentage(0x61, 0, 4) == 0.25 and math.mode(0, 4) == 0x61 }
rule constant { condition: math.serial_correlation("aaaa") == -100000 and not defined math.monte_carlo_pi("short") }
rule now { condition: time.now() > 1700000000 }
`, "abcd")
	want := "md5,sha,crc,out_of_range,stats,helpers,counts,constant,now"
	if strings.Join(got, ",") != want {
		t.Fatalf("%v, want %s", got, want)
	}
	if got := scanText(t, `import "math" rule e { condition: math.entropy(0, filesize) == 8 and math.in_range(math.entropy(0, 256), 7.99, 8.0) }`, string(all)); len(got) != 1 {
		t.Fatal("entropy of all byte values")
	}
}

func TestModuleErrors(t *testing.T) {
	for src, want := range map[string]string{
		`import "elf" rule r { condition: true }`:                                     "not supported",
		`rule r { condition: hash.md5("a") == "" }`:                                   "without import",
		`rule r { condition: elf.type == 1 }`:                                         "not supported",
		`import "hash" rule r { condition: hash.nope("a") }`:                          "has no field",
		`import "hash" rule r { condition: hash.md5(1) == "" }`:                       "wrong arguments",
		`import "hash" rule r { condition: hash.md5 == "" }`:                          "is a function",
		`import "hash" rule r { condition: hash == 1 }`:                               "is a module",
		`import "tests" rule r { condition: tests.items }`:                            "not a value",
		`import "tests" rule r { condition: tests.items["a"].size == 1 }`:             "integer index",
		`import "tests" rule r { condition: for any k, v in tests.items : ( true ) }`: "one name",
		`import "tests" rule r { condition: for any x in tests.ratio : ( true ) }`:    "not an array",
	} {
		_, err := Compile(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", src, err, want)
		}
	}
}
