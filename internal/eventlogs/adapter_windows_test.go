package eventlogs

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"testing"
	"time"
)

func TestNativeEventQueriesAndPaging(t *testing.T) {
	a := NewAdapter()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	support, e := a.Probe(ctx)
	if e != nil || !SupportValid(support) || support.System != "readable" {
		t.Fatal("native System log unavailable", e)
	}
	q := protocol.EventQuery{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Filter: protocol.EventFilter{Channel: "System", From: time.Now().Add(-24 * time.Hour).Unix(), To: time.Now().Unix(), Level: -1, EventID: -1, Limit: 2}}
	r := a.Query(ctx, q)
	if r.Outcome != "ok" || !ResultValid(r, q.Filter) {
		t.Fatal("native query failed", r.Outcome)
	}
	if r.More {
		q.Filter.Before = r.NextBefore
		next := a.Query(ctx, q)
		if next.Outcome != "ok" || !ResultValid(next, q.Filter) {
			t.Fatal("native pagination failed", next.Outcome)
		}
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	r = a.Query(cancelled, q)
	if r.Outcome != "timed_out" || len(r.Events) != 0 {
		t.Fatal("cancelled query returned contents")
	}
	// A raw XPath predicate is combined with the structured filter.
	q.Filter.Before = 0
	all := a.Query(ctx, q)
	q.Filter.XPath = "*[System[Level>=0]]"
	same := a.Query(ctx, q)
	if same.Outcome != "ok" || len(same.Events) != len(all.Events) {
		t.Fatal("matching XPath changed the result", same.Outcome, len(same.Events), len(all.Events))
	}
	q.Filter.XPath = "*[System[EventID=65535 and Level=255]]"
	if none := a.Query(ctx, q); none.Outcome != "ok" || len(none.Events) != 0 {
		t.Fatal("narrowing XPath ignored", none.Outcome, len(none.Events))
	}
	q.Filter.XPath = ""
	q.Filter.Channel = "OpenRMM-No-Such-Channel/Operational"
	if r = a.Query(ctx, q); r.Outcome != "unavailable" {
		t.Fatal("unknown channel", r.Outcome)
	}
	if len(support.Channels) != len(KeyChannels) || support.Channels["Security"] == "" {
		t.Fatal("key channels not probed", support.Channels)
	}
}
