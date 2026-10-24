package cpu

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

type fakeCollector struct {
	value protocol.CPU
	err   error
}

func (c fakeCollector) Collect(context.Context) (protocol.CPU, error) { return c.value, c.err }

func TestCPUCounterDeltas(t *testing.T) {
	for _, test := range []struct {
		name          string
		before, after times
		want          float64
		fail          bool
	}{
		{"kernel includes idle", times{100, 200, 300}, times{120, 260, 340}, 80, false},
		{"idle", times{}, times{100, 100, 0}, 0, false}, {"busy", times{}, times{0, 50, 50}, 100, false},
		{"user only", times{}, times{0, 0, 100}, 100, false},
		{"idle backwards", times{10, 20, 30}, times{9, 40, 50}, 0, true},
		{"kernel backwards", times{10, 20, 30}, times{20, 19, 50}, 0, true},
		{"user backwards", times{10, 20, 30}, times{20, 40, 29}, 0, true},
		{"zero delta", times{10, 20, 30}, times{10, 20, 30}, 0, true},
		{"idle exceeds kernel", times{}, times{51, 50, 100}, 0, true},
		{"overflow", times{}, times{0, math.MaxUint64, 1}, 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := utilization(test.before, test.after)
			if (err != nil) != test.fail || (!test.fail && got != test.want) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestSamplingWaitErrorsAndCancellation(t *testing.T) {
	start := time.Unix(1800000000, 0)
	for _, elapsed := range []time.Duration{time.Second, 1500 * time.Millisecond, 999 * time.Millisecond, 6 * time.Second} {
		reads, clocks := 0, 0
		value, err := sample(context.Background(), func() (times, error) {
			reads++
			if reads == 1 {
				return times{}, nil
			}
			return times{20, 60, 40}, nil
		}, func(context.Context) error { return nil }, func() time.Time {
			clocks++
			if clocks == 1 {
				return start
			}
			return start.Add(elapsed)
		})
		valid := elapsed >= time.Second && elapsed <= 5*time.Second
		if (err == nil) != valid || (valid && (value.UsagePercent != 80 || value.SampleMilliseconds != uint32(elapsed/time.Millisecond))) {
			t.Fatal("incorrect sampled result", value, err)
		}
	}
	for _, failRead := range []int{1, 2} {
		reads := 0
		_, err := sample(context.Background(), func() (times, error) {
			reads++
			if reads == failRead {
				return times{}, errors.New("read failed")
			}
			return times{}, nil
		}, func(context.Context) error { return nil }, time.Now)
		if err == nil || reads != failRead {
			t.Fatal("read failure ignored")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	reads := 0
	_, err := sample(ctx, func() (times, error) { reads++; return times{}, nil }, func(context.Context) error { cancel(); return nil }, time.Now)
	if !errors.Is(err, context.Canceled) || reads != 1 {
		t.Fatal("canceled sample read again")
	}
	if !errors.Is(waitSample(ctx), context.Canceled) {
		t.Fatal("sample timer ignored cancellation")
	}
	reads = 0
	_, err = sample(ctx, func() (times, error) { reads++; return times{}, nil }, waitSample, time.Now)
	if !errors.Is(err, context.Canceled) || reads != 0 {
		t.Fatal("pre-canceled collection read counters")
	}
	_, err = sample(context.Background(), func() (times, error) { return times{}, features.ErrUnsupported }, waitSample, time.Now)
	if !errors.Is(err, features.ErrUnsupported) {
		t.Fatal("unsupported OS/group lost")
	}
}

func TestCPUAdapterAndStrictSchema(t *testing.T) {
	for _, usage := range []float64{0, 12.5, 100} {
		data, err := (Module{fakeCollector{value: protocol.CPU{UsagePercent: usage, SampleMilliseconds: 1000}}}).Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{`null`, `{}`, `{"usage_percent":0}`, `{"sample_ms":1000}`, `{"usage_percent":null,"sample_ms":1000}`,
		`{"usage_percent":-1,"sample_ms":1000}`, `{"usage_percent":100.1,"sample_ms":1000}`, `{"usage_percent":1e999,"sample_ms":1000}`,
		`{"usage_percent":1,"sample_ms":999}`, `{"usage_percent":1,"sample_ms":5001}`, `{"usage_percent":1,"sample_ms":1000.5}`,
		`{"usage_percent":1,"sample_ms":-1}`, `{"usage_percent":1,"sample_ms":1000,"processes":[]}`,
		`{"usage_percent":1,"sample_ms":1000,"device_id":"forged"}`, `{"usage_percent":1,"sample_ms":1000,"received_at":1}`,
		`{"usage_percent":1,"sample_ms":1000} {}`,
	} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: "ok", Data: json.RawMessage(body)}); !errors.Is(err, features.ErrReport) {
			t.Fatalf("bad CPU report accepted: %s", body)
		}
	}
	for _, usage := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if Valid(protocol.CPU{UsagePercent: usage, SampleMilliseconds: 1000}) {
			t.Fatal("non-finite usage accepted")
		}
	}
	for _, status := range []string{"failed", "disabled", "unsupported"} {
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status}); err != nil {
			t.Fatal(err)
		}
		if _, err := Normalize(protocol.FeatureReport{Capability: Capability, Status: status, Data: json.RawMessage(`{}`)}); err == nil {
			t.Fatal("non-success data accepted")
		}
	}
	for _, cap := range []protocol.Capability{{Name: "cpu", Version: 0}, {Name: "cpu", Version: 1000}, {Name: "unknown", Version: 1}} {
		if _, err := Normalize(protocol.FeatureReport{Capability: cap, Status: "ok"}); err == nil {
			t.Fatal("unknown capability accepted")
		}
	}
	newer, err := Normalize(protocol.FeatureReport{Capability: protocol.Capability{Name: "cpu", Version: 2}, Status: "ok", Data: json.RawMessage(`{"future":true}`)})
	if err != nil || newer.Status != "unsupported" || len(newer.Data) != 0 {
		t.Fatal("newer payload not discarded")
	}
	if _, err := (Module{fakeCollector{err: errors.New("collector unavailable")}}).Collect(context.Background()); err == nil {
		t.Fatal("adapter error lost")
	}
	if _, err := (Module{fakeCollector{}}).Collect(context.Background()); err == nil {
		t.Fatal("invalid collector value accepted")
	}
}
