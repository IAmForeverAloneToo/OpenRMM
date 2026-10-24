package storage

import (
	"context"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"sync"
	"testing"
	"time"
)

func openingAlert(t *testing.T) (*Store, Device, time.Time) {
	s, d, now := alertFixture(t)
	cpuReading(t, s, d, now, 99, "ok")
	sweep(t, s, now)
	for sec := 15; sec < 60; sec += 15 {
		sweep(t, s, now.Add(time.Duration(sec)*time.Second))
	}
	cpuReading(t, s, d, now.Add(time.Minute), 99, "ok")
	sweep(t, s, now.Add(time.Minute))
	return s, d, now.Add(time.Minute)
}
func TestMailClaimIsAtomicAndUnknownNeverReplayed(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var claimed []int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _, e := s.ClaimAlertMail(ctx, "test-mail", now)
			if e != nil {
				t.Error(e)
			}
			if id != 0 {
				mu.Lock()
				claimed = append(claimed, id)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimed) != 1 {
		t.Fatal("concurrent duplicate send", len(claimed))
	}
	if e := s.FinishAlertMail(ctx, claimed[0], alerting.MailResult{Status: "unknown", Reason: "acceptance_unknown"}, now); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeAlerts(ctx, 120*time.Second, "test-mail", now); e != nil {
		t.Fatal(e)
	}
	if id, _, e := s.ClaimAlertMail(ctx, "test-mail", now); e != nil || id != 0 {
		t.Fatal("ambiguous mail replayed")
	}
	list, e := s.AlertDeliveries(ctx, d.ID)
	if e != nil || len(list) != 1 || list[0].Status != "unknown" {
		t.Fatal("delivery outcome lost", e)
	}
}
func TestMailRetryPauseAndInterruptedSend(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	id, _, e := s.ClaimAlertMail(ctx, "test-mail", now)
	if e != nil || id == 0 {
		t.Fatal(e)
	}
	if e = s.FinishAlertMail(ctx, id, alerting.MailResult{Status: "retry", Reason: "temporary"}, now); e != nil {
		t.Fatal(e)
	}
	if id, _, e = s.ClaimAlertMail(ctx, "test-mail", now); e != nil || id != 0 {
		t.Fatal("retry delay ignored")
	}
	if e = s.PauseAlertMail(ctx, true, "admin", now); e != nil {
		t.Fatal(e)
	}
	if e = s.PauseAlertMail(ctx, false, "admin", now); e != nil {
		t.Fatal(e)
	}
	if id, _, e = s.ClaimAlertMail(ctx, "test-mail", now.Add(time.Minute)); e != nil || id != 0 {
		t.Fatal("pause/resume replayed old notice")
	}
	list, e := s.AlertDeliveries(ctx, d.ID)
	if e != nil || len(list) != 1 || list[0].Status != "cancelled" {
		t.Fatal("pause did not cancel queue")
	}
	s, d, now = openingAlert(t)
	id, _, e = s.ClaimAlertMail(ctx, "test-mail", now)
	if e != nil || id == 0 {
		t.Fatal(e)
	}
	if e = s.InitializeAlerts(ctx, 120*time.Second, "test-mail", now); e != nil {
		t.Fatal(e)
	}
	list, e = s.AlertDeliveries(ctx, d.ID)
	if e != nil || list[0].Status != "unknown" {
		t.Fatal("interrupted send replayable")
	}
}
func TestAcknowledgmentSuppressesQueuedEmail(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	a := alertsFor(t, s, d.ID)
	if e := s.AcknowledgeAlert(ctx, a[0].ID, "admin", now); e != nil {
		t.Fatal(e)
	}
	if id, _, e := s.ClaimAlertMail(ctx, "test-mail", now); e != nil || id != 0 {
		t.Fatal("acknowledged opening delivered")
	}
}
