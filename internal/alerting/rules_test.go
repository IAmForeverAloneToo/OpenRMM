package alerting

import (
	"testing"
	"time"
)

func TestQualificationDistinctSamplesUnknownAndRecovery(t *testing.T) {
	r := Rule{Kind: "cpu", Enabled: true, Threshold: 90, HoldSeconds: 60, RecoverySeconds: 60, Severity: "warning", Revision: 1}
	now := time.Unix(1800000000, 0)
	s := State{}
	apply := func(at int64, c string) string {
		var event string
		s, event = Apply(r, s, Observation{Condition: c, At: now.Unix() + at}, now.Add(time.Duration(at)*time.Second))
		return event
	}
	if apply(0, "bad") != "" {
		t.Fatal("single sample fired")
	}
	var event string
	s, event = Apply(r, s, Observation{Condition: "bad", At: now.Unix()}, now.Add(time.Minute))
	if event != "" || s.Samples != 1 {
		t.Fatal("cached sample matured")
	}
	if apply(60, "unknown") != "" || s.Since != 0 {
		t.Fatal("unknown did not reset")
	}
	if apply(61, "bad") != "" || apply(121, "bad") != "open" {
		t.Fatal("distinct sustained readings did not fire")
	}
	s.Incident = "incident"
	if apply(122, "unknown") != "" || s.Incident == "" {
		t.Fatal("unknown cleared incident")
	}
	if apply(123, "good") != "" || apply(183, "good") != "resolve" {
		t.Fatal("fresh recovery not qualified")
	}
}
func TestGapsExactBoundariesAndFuture(t *testing.T) {
	r := Rule{Kind: "memory", Enabled: true, Threshold: 90, HoldSeconds: 60, RecoverySeconds: 60, Severity: "critical", Revision: 1}
	base := int64(1800000000)
	s, _ := Apply(r, State{}, Observation{Condition: "bad", At: base}, time.Unix(base, 0))
	s, e := Apply(r, s, Observation{Condition: "bad", At: base + 120}, time.Unix(base+120, 0))
	if e != "" || s.Samples != 1 {
		t.Fatal("stale gap qualified")
	}
	s, e = Apply(r, s, Observation{Condition: "good", At: base + 300}, time.Unix(base+121, 0))
	if e != "" || s.Condition != "unknown" {
		t.Fatal("future sample accepted")
	}
}

func FuzzAlertQualification(f *testing.F) {
	f.Add(int64(60), float64(95), true)
	f.Fuzz(func(t *testing.T, delta int64, value float64, bad bool) {
		base := int64(1800000000)
		delta = delta % 1000
		r := Rule{Kind: "cpu", Enabled: true, Threshold: 90, HoldSeconds: 60, RecoverySeconds: 60, Severity: "warning", Revision: 1}
		s := State{Condition: "bad", Since: base, Samples: 1, LastSample: base, LastEvaluated: base, Incident: "incident"}
		condition := "good"
		if bad {
			condition = "bad"
		}
		next, event := Apply(r, s, Observation{Condition: condition, At: base + delta, Value: &value}, time.Unix(base+300, 0))
		if next.Samples > 2 || next.Samples < 0 || next.Incident != s.Incident {
			t.Fatal("qualification invariant")
		}
		if (delta > 300 || delta < 180) && event != "" {
			t.Fatal("future/stale sample changed incident")
		}
	})
}
