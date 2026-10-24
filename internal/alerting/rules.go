// Package alerting defines alert qualification independently of storage and OS.
package alerting

import (
	"math"
	"time"
)

type Rule struct {
	Kind            string `json:"kind"`
	Enabled         bool   `json:"enabled"`
	Threshold       int    `json:"threshold"`
	HoldSeconds     int64  `json:"hold_seconds"`
	RecoverySeconds int64  `json:"recovery_seconds"`
	Severity        string `json:"severity"`
	Email           bool   `json:"email"`
	Revision        int64  `json:"revision"`
}

var Kinds = []string{"offline", "disk_space", "cpu", "memory"}

func Title(kind string) string {
	switch kind {
	case "offline":
		return "Device offline"
	case "disk_space":
		return "Low system disk space"
	case "cpu":
		return "High CPU usage"
	case "memory":
		return "High RAM usage"
	}
	return "Unknown alert"
}
func RuleValid(r Rule) bool {
	known := false
	for _, k := range Kinds {
		if r.Kind == k {
			known = true
		}
	}
	return known && ((r.Kind == "offline" && r.Threshold == 0) || (r.Kind != "offline" && r.Threshold >= 1 && r.Threshold <= 99)) && r.HoldSeconds >= 60 && r.HoldSeconds <= 86400 && r.RecoverySeconds >= 60 && r.RecoverySeconds <= 3600 && (r.Severity == "warning" || r.Severity == "critical") && r.Revision >= 1
}
func Freshness(kind string) int64 {
	if kind == "disk_space" {
		return 600
	}
	return 120
}

type State struct {
	Condition     string   `json:"condition"`
	Since         int64    `json:"since"`
	Samples       int      `json:"samples"`
	LastSample    int64    `json:"last_sample"`
	LastEvaluated int64    `json:"last_evaluated"`
	Incident      string   `json:"incident"`
	Value         *float64 `json:"value"`
}
type Observation struct {
	Condition string
	At        int64
	Value     *float64
}

// Apply only qualifies from distinct observations. Re-reading a cached metric
// cannot mature it. Unknown breaks qualification and never resolves an incident.
func Apply(r Rule, s State, o Observation, now time.Time) (State, string) {
	return qualify(r.Enabled && RuleValid(r), r.HoldSeconds, r.RecoverySeconds, Freshness(r.Kind), s, o, now)
}

// ApplyHealth shares distinct-observation qualification without extending the
// closed set of built-in monitoring policy rules.
func ApplyHealth(enabled bool, hold, recovery int64, s State, o Observation, now time.Time) (State, string) {
	valid := enabled && hold >= 60 && hold <= 86400 && recovery >= 60 && recovery <= 3600
	return qualify(valid, hold, recovery, 120, s, o, now)
}

func qualify(valid bool, hold, recovery, freshness int64, s State, o Observation, now time.Time) (State, string) {
	n := now.Unix()
	previousEvaluation := s.LastEvaluated
	s.LastEvaluated = n
	unknown := func() (State, string) {
		s.Condition = "unknown"
		s.Since = 0
		s.Samples = 0
		s.Value = nil
		return s, ""
	}
	if n < previousEvaluation {
		s.LastSample = 0
		return unknown()
	}
	if !valid || o.At <= 0 || o.At > n || n-o.At >= freshness || (o.Value != nil && (math.IsNaN(*o.Value) || math.IsInf(*o.Value, 0))) {
		return unknown()
	}
	if o.At < s.LastSample {
		s.LastSample = 0
		return unknown()
	}
	if o.Condition != "bad" && o.Condition != "good" {
		if o.At > s.LastSample {
			s.LastSample = o.At
		}
		return unknown()
	}
	if o.At == s.LastSample {
		return s, ""
	}
	if o.Condition != s.Condition || o.At-s.LastSample >= freshness || s.Since == 0 {
		s.Since = o.At
		s.Samples = 0
	}
	s.LastSample = o.At
	s.Condition = o.Condition
	s.Value = o.Value
	if s.Samples < 2 {
		s.Samples++
	}
	if s.Condition == "bad" && s.Incident == "" && s.Samples >= 2 && o.At-s.Since >= hold {
		return s, "open"
	}
	if s.Condition == "good" && s.Incident != "" && s.Samples >= 2 && o.At-s.Since >= recovery {
		return s, "resolve"
	}
	return s, ""
}
