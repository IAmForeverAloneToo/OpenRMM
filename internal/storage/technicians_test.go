package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func technicianFixture(t *testing.T, s *Store, now time.Time, access TechnicianAccess) Session {
	t.Helper()
	ctx := context.Background()
	var configured int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM administrators").Scan(&configured); e != nil {
		t.Fatal(e)
	}
	if configured == 0 {
		if e := s.SetAdministrator(ctx, Administrator{Username: "admin", PasswordHash: "hash", TOTPCipher: []byte("cipher")}, nil, false, now); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.ConfirmAdministrator(ctx, 1, 1, now); e != nil {
		t.Fatal(e)
	}
	c := TechnicianChange{Action: "create", ID: strings.Repeat("b", 32), Username: "helper", Enabled: true, Access: access}
	digest, e := s.ChangeTechnician(ctx, c, "admin", "", "", now)
	if e != nil {
		t.Fatal(e)
	}
	invite := strings.Repeat("a", 64)
	confirm := strings.Repeat("c", 64)
	if _, e = s.ChangeTechnician(ctx, c, "admin", digest, invite, now); e != nil {
		t.Fatal(e)
	}
	if e = s.BeginTechnicianActivation(ctx, c.ID, invite, confirm, "hash", []byte("cipher"), []string{"recovery-hash"}, now); e != nil {
		t.Fatal(e)
	}
	if e = s.ConfirmTechnicianActivation(ctx, c.ID, confirm, 1, now); e != nil {
		t.Fatal(e)
	}
	v := Session{TokenHash: "technician-session", CSRF: "csrf", CreatedAt: now.Unix(), LastSeenAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	if e = s.CompleteTechnicianLogin(ctx, c.ID, 1, 2, "", v, now); e != nil {
		t.Fatal(e)
	}
	v, e = s.Session(ctx, v.TokenHash, now)
	if e != nil || v.Technician == nil {
		t.Fatal("missing technician session", e)
	}
	return v
}
func TestTechnicianScopeChangesStopDesktopAndUndispatchedWork(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab"}, now)
	v := technicianFixture(t, s, now, TechnicianAccess{Groups: []string{"lab"}, Services: true, Desktop: true})
	if e := s.AuthorizeDevice(ctx, v, d.ID, "services"); e != nil {
		t.Fatal(e)
	}
	if e := s.CheckDesktopAuthorization(ctx, d.ID, v.TokenHash, now); e != nil {
		t.Fatal(e)
	}
	if e := s.AuthorizeDevice(ctx, v, d.ID, "processes"); !errors.Is(e, ErrForbidden) {
		t.Fatal("permission bypass")
	}
	a := actionRequest(d, strings.Repeat("c", 32))
	a.Actor = v.Actor()
	if e := s.QueueServiceAction(ctx, a, now, time.Minute); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now)
	if e := s.CheckDesktopAuthorization(ctx, d.ID, v.TokenHash, now); e == nil {
		t.Fatal("desktop scope not rechecked")
	}
	// Restoring membership before the agent polls must not revive old intent.
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID, GroupID: "lab"}, now)
	dispatch, e := s.DispatchServiceAction(ctx, d.ID, d.Fingerprint, now)
	if e != nil || dispatch.Action != nil {
		t.Fatal("lost-scope command dispatched", e)
	}
	actions, e := s.ServiceActions(ctx, d.ID, now)
	if e != nil || len(actions) != 1 || actions[0].Status != "cancelled" {
		t.Fatal("queue not cancelled", e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: d.ID}, now)
	a.ID = strings.Repeat("d", 32)
	if e = s.QueueServiceAction(ctx, a, now, time.Minute); !errors.Is(e, ErrForbidden) {
		t.Fatal("queue authorization missing", e)
	}
	o := organizationRead(t, s)
	_, e = s.ChangeOrganization(ctx, OrganizationChange{Action: "group-delete", ID: "lab", Revision: o.Revision}, "admin", "", now)
	if !errors.Is(e, ErrOrganization) {
		t.Fatal("referenced scope group deleted/reusable", e)
	}
}
func TestTechnicianReviewsNamespaceAndAuditAreAtomic(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	c := TechnicianChange{Action: "save", ID: v.Technician.ID, Username: "helper", Enabled: true, Revision: 1, Access: TechnicianAccess{AllDevices: true, Desktop: true}}
	digest, e := s.ChangeTechnician(ctx, c, "admin", "", "", now)
	if e != nil {
		t.Fatal(e)
	}
	bad := c
	bad.Access.Services = true
	if _, e = s.ChangeTechnician(ctx, bad, "admin", digest, "", now); !errors.Is(e, ErrTechnician) {
		t.Fatal("tamper accepted")
	}
	if _, e = s.db.Exec(`CREATE TRIGGER deny_technician_audit BEFORE INSERT ON audit_events WHEN NEW.action LIKE 'technician_%' BEGIN SELECT RAISE(ABORT,'test'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeTechnician(ctx, c, "admin", digest, "", now); e == nil {
		t.Fatal("unaudited mutation accepted")
	}
	if _, e = s.Session(ctx, v.TokenHash, now); e != nil {
		t.Fatal("audit failure partially invalidated sessions")
	}
	if _, e = s.db.Exec("DROP TRIGGER deny_technician_audit"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ChangeTechnician(ctx, c, "admin", digest, "", now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Session(ctx, v.TokenHash, now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("account edit left old session valid")
	}
	if _, e = s.ChangeTechnician(ctx, c, "admin", digest, "", now); !errors.Is(e, ErrTechnician) {
		t.Fatal("replay accepted")
	}
	if e = s.SetAdministrator(ctx, Administrator{Username: "helper", PasswordHash: "hash", TOTPCipher: []byte("cipher")}, nil, true, now); e == nil {
		t.Fatal("owner/technician username collision")
	}
	if e = s.AuthorizeDevice(ctx, Session{Technician: &Technician{Enabled: true, Confirmed: true, Access: TechnicianAccess{AllDevices: true}}}, strings.Repeat("f", 32), "read"); !errors.Is(e, ErrForbidden) {
		t.Fatal("unknown device exposed")
	}
}

func TestTechnicianProcessAndEventDispatchRecheckDisabledAccount(t *testing.T) {
	t.Run("processes", func(t *testing.T) {
		s, d, now := processActionFixture(t)
		ctx := context.Background()
		v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}, Processes: true})
		a := processActionRequest(d, strings.Repeat("c", 32))
		a.Actor = v.Actor()
		if e := s.QueueProcessAction(ctx, a, now, time.Minute); e != nil {
			t.Fatal(e)
		}
		c := TechnicianChange{Action: "save", ID: v.Technician.ID, Username: v.Username, Revision: v.Version, Access: v.Technician.Access, Enabled: false}
		digest, e := s.ChangeTechnician(ctx, c, "admin", "", "", now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.ChangeTechnician(ctx, c, "admin", digest, "", now); e != nil {
			t.Fatal(e)
		}
		var queued int
		if e = s.db.QueryRow("SELECT COUNT(*) FROM process_actions WHERE status='queued'").Scan(&queued); e != nil || queued != 0 {
			t.Fatal("disable left queued work until next poll")
		}
		result, e := s.DispatchProcessAction(ctx, d.ID, d.Fingerprint, now)
		if e != nil || result.Action != nil {
			t.Fatal("disabled actor dispatched", e)
		}
		a.ID = strings.Repeat("d", 32)
		if e = s.QueueProcessAction(ctx, a, now, time.Minute); !errors.Is(e, ErrForbidden) {
			t.Fatal("disabled actor queued")
		}
	})
	t.Run("events", func(t *testing.T) {
		s, d, now, q := eventFixture(t)
		ctx := context.Background()
		v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}, Events: true})
		q.Actor = v.Actor()
		if e := s.QueueEventQuery(ctx, q, now, time.Minute); e != nil {
			t.Fatal(e)
		}
		c := TechnicianChange{Action: "save", ID: v.Technician.ID, Username: v.Username, Revision: v.Version, Access: v.Technician.Access, Enabled: false}
		digest, e := s.ChangeTechnician(ctx, c, "admin", "", "", now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.ChangeTechnician(ctx, c, "admin", digest, "", now); e != nil {
			t.Fatal(e)
		}
		result, e := s.DispatchEventQuery(ctx, d.ID, d.Fingerprint, now)
		if e != nil || result.Query != nil {
			t.Fatal("disabled actor dispatched", e)
		}
		q.ID = strings.Repeat("d", 32)
		if e = s.QueueEventQuery(ctx, q, now, time.Minute); !errors.Is(e, ErrForbidden) {
			t.Fatal("disabled actor queued")
		}
	})
}

func TestTechnicianAlertScopeAppliesBeforeHistoryLimits(t *testing.T) {
	s, d, now := openingAlert(t)
	ctx := context.Background()
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 205; i++ {
		id := fmt.Sprintf("%032x", i)
		alert := fmt.Sprintf("%032x", i+1000)
		if _, e = tx.Exec("INSERT INTO devices(id,hostname,os,architecture,enrolled_at,certificate_pem,fingerprint) VALUES(?,?,'windows','amd64',?,'test',?)", id, "outside", now.Unix(), id); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("INSERT INTO alerts(id,device_id,hostname,kind,severity,threshold,hold_seconds,status,opened_at,last_seen) VALUES(?,?,'outside','cpu','critical',90,60,'active',?,?)", alert, id, now.Unix(), now.Unix()); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec("INSERT INTO alert_deliveries(alert_id,event,config_id,status,created_at,next_attempt) VALUES(?,'opened','test-mail','queued',?,?)", alert, now.Unix(), now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	owner, e := s.Alerts(ctx, "")
	if e != nil || len(owner) != 200 {
		t.Fatal("fixture did not exceed incident history bound")
	}
	for _, a := range owner {
		if a.DeviceID == d.ID {
			t.Fatal("fixture did not displace permitted warning")
		}
	}
	visible, e := s.AlertsForSession(ctx, v, "")
	if e != nil || len(visible) != 1 || visible[0].DeviceID != d.ID {
		t.Fatal("scope filtered after incident limit", e)
	}
	mail, e := s.AlertDeliveriesForSession(ctx, v, "")
	if e != nil || len(mail) != 1 || mail[0].AlertID != visible[0].ID {
		t.Fatal("scope filtered after notice limit", e)
	}
	states, e := s.AlertStatesForSession(ctx, v, "")
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range states {
		if state.DeviceID != d.ID {
			t.Fatal("state escaped scope")
		}
	}
}
