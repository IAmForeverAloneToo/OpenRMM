package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceActivityPermissionsReadOnlyAndScope(t *testing.T) {
	s, d, version, now := scriptFixture(t)
	ctx := context.Background()
	if e := s.QueueScriptRun(ctx, scriptRequest(d, version, strings.Repeat("a", 32)), now, 120*time.Second); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO file_jobs(id,device_id,actor,job_json,status,reserve_bytes,created_at,expires_at,payload_until)VALUES(?,?,'admin','private-path','queued',0,?,?,?)`, strings.Repeat("f", 32), d.ID, now.Unix(), now.Add(time.Minute).Unix(), now.Add(time.Minute).Unix()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO service_actions(id,device_id,service_name,action,actor,created_at,expires_at,status,outcome)VALUES(?,?,'Private service','start','admin',?,?,'unknown','private result')`, strings.Repeat("c", 32), d.ID, now.Unix(), now.Add(time.Minute).Unix()); e != nil {
		t.Fatal(e)
	}
	owner, e := s.WorkspaceActivity(ctx, Session{}, d.ID, now)
	if e != nil || owner.Pending != 2 || len(owner.Recent) != 3 {
		t.Fatal(owner, e)
	}
	data, _ := json.Marshal(owner)
	for _, secret := range []string{"private parameter", "private-path", "Private service", "private result"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("projection copied sensitive job data")
		}
	}
	v := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}})
	limited, e := s.WorkspaceActivity(ctx, v, d.ID, now)
	if e != nil || limited.Pending != 0 || len(limited.Recent) != 1 || limited.Recent[0].Kind != "services" {
		t.Fatal(limited, e)
	}
	if _, e = s.WorkspaceActivity(ctx, v, strings.Repeat("e", 32), now); !errors.Is(e, ErrForbidden) {
		t.Fatal("cross-device projection", e)
	}
	if _, e = s.db.Exec("UPDATE technicians SET revision=revision+1"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.WorkspaceActivity(ctx, v, d.ID, now); !errors.Is(e, ErrForbidden) {
		t.Fatal("stale account read", e)
	}
	var status string
	if e = s.db.QueryRow("SELECT status FROM script_runs WHERE id=?", strings.Repeat("a", 32)).Scan(&status); e != nil || status != "queued" {
		t.Fatal("read-only projection changed job", status, e)
	}
}
func TestWorkspaceActivityHasBoundedRetainedHistory(t *testing.T) {
	s, d, now := actionFixture(t)
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		id := strings.Repeat("a", 30) + string("0123456789abcdef"[i/16]) + string("0123456789abcdef"[i%16])
		if _, e := s.db.Exec(`INSERT INTO service_actions(id,device_id,service_name,action,actor,created_at,expires_at,status)VALUES(?,?,'Fixture','start','admin',?,?,'succeeded')`, id, d.ID, now.Unix()-int64(i), now.Unix()); e != nil {
			t.Fatal(e)
		}
	}
	got, e := s.WorkspaceActivity(ctx, Session{}, d.ID, now)
	if e != nil || len(got.Recent) != 10 || got.Recent[0].At != now.Unix() {
		t.Fatal(got, e)
	}
}
