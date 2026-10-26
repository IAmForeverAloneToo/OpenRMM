package server

import (
	"encoding/json"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
)

// The dashboard sets the nightly schedule (handed to the updater as a
// file), asks for a backup now and shows the updater's report.
func TestServerBackupAPI(t *testing.T) {
	base := newAPIFixture(t)
	dir := t.TempDir()
	updates := &serverUpdates{dir: dir, current: serverupdate.Current{Version: "1.0.0", Sequence: 10}}
	s := httptest.NewTLSServer(handler(base.store, base.auth, base.devices, updates, nil))
	t.Cleanup(s.Close)
	client := s.Client()
	client.Jar, _ = cookiejar.New(nil)
	f := &apiFixture{server: s, client: client, store: base.store, devices: base.devices, auth: base.auth, secret: base.secret, recovery: base.recovery}
	f.login(t)
	type view struct {
		Updater  bool `json:"updater"`
		Settings struct {
			Enabled  bool  `json:"enabled"`
			Hour     int   `json:"hour"`
			Revision int64 `json:"revision"`
		} `json:"settings"`
		Report *serverupdate.BackupReport `json:"report"`
	}
	get := func() view {
		t.Helper()
		resp, body := f.do(t, "GET", "/api/v1/server/backups", nil, false)
		var v view
		if resp.StatusCode != 200 || json.Unmarshal(body, &v) != nil {
			t.Fatal(resp.StatusCode, string(body))
		}
		return v
	}
	if v := get(); v.Updater || v.Report != nil || !v.Settings.Enabled || v.Settings.Hour != 3 {
		t.Fatalf("defaults %+v", v)
	}
	if resp, _ := f.do(t, "POST", "/api/v1/server/backups/run", nil, true); resp.StatusCode != 409 {
		t.Fatal("backup requested without an updater", resp.StatusCode)
	}
	if resp, _ := f.do(t, "PUT", "/api/v1/server/backups/settings", map[string]any{"enabled": true, "hour": 24, "revision": 1}, true); resp.StatusCode != 400 {
		t.Fatal("invalid hour accepted", resp.StatusCode)
	}
	if resp, body := f.do(t, "PUT", "/api/v1/server/backups/settings", map[string]any{"enabled": true, "hour": 22, "revision": 1}, true); resp.StatusCode != 200 {
		t.Fatal("settings", resp.StatusCode, string(body))
	}
	if resp, _ := f.do(t, "PUT", "/api/v1/server/backups/settings", map[string]any{"enabled": false, "hour": 1, "revision": 1}, true); resp.StatusCode != 409 {
		t.Fatal("stale revision accepted", resp.StatusCode)
	}
	var schedule serverupdate.BackupSchedule
	if b, e := os.ReadFile(filepath.Join(dir, serverupdate.ScheduleFile)); e != nil || json.Unmarshal(b, &schedule) != nil || !schedule.Enabled || schedule.Hour != 22 {
		t.Fatal("schedule not handed to the updater", schedule, e)
	}
	// An updater is present: its heartbeat and report are shown, and a
	// backup can be requested once until the updater picks it up.
	now := time.Now().Unix()
	status, _ := json.Marshal(serverupdate.Status{Phase: "idle", UpdatedAt: now, Alive: now, Updater: serverupdate.UpdaterRevision})
	report, _ := json.Marshal(serverupdate.BackupReport{Updater: 1, UpdatedAt: now, Schedule: schedule, Backups: []serverupdate.BackupInfo{{Name: "nightly-20270115-220000", Kind: "nightly", CreatedAt: now, Live: true, Size: 1000}}})
	os.WriteFile(filepath.Join(dir, serverupdate.StatusFile), status, 0600)
	os.WriteFile(filepath.Join(dir, serverupdate.BackupReportFile), report, 0600)
	if v := get(); !v.Updater || v.Report == nil || len(v.Report.Backups) != 1 || v.Settings.Hour != 22 {
		t.Fatalf("with updater %+v", v)
	}
	if resp, body := f.do(t, "POST", "/api/v1/server/backups/run", nil, true); resp.StatusCode != 202 {
		t.Fatal("backup request", resp.StatusCode, string(body))
	}
	if _, e := os.Stat(filepath.Join(dir, serverupdate.BackupRequestFile)); e != nil {
		t.Fatal("request not handed to the updater")
	}
	if resp, _ := f.do(t, "POST", "/api/v1/server/backups/run", nil, true); resp.StatusCode != 409 {
		t.Fatal("second request accepted while one waits", resp.StatusCode)
	}
}
