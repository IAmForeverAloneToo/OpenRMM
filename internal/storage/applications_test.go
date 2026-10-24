package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/applications"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
)

func rollbackApplicationSchema(t *testing.T, s *Store) {
	t.Helper()
	rollbackFileSchema(t, s)
	var n int
	if e := s.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version=21").Scan(&n); e != nil {
		t.Fatal(e)
	}
	if n == 0 {
		return
	}
	for _, q := range []string{"DROP TRIGGER application_run_status", "DROP TABLE application_deployments", "DROP TABLE application_versions", "DROP TABLE applications", "DROP TABLE application_state", "DELETE FROM schema_migrations WHERE version=21"} {
		if _, e := s.db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
}
func applicationFixture(t *testing.T) (*Store, Device, ApplicationVersion, time.Time) {
	t.Helper()
	s, d, _, now := scriptFixture(t)
	if e := s.SetAdministrator(context.Background(), Administrator{Username: "admin", PasswordHash: "hash", TOTPCipher: []byte("cipher")}, nil, false, now); e != nil {
		t.Fatal(e)
	}
	v := applicationSave(t, s, strings.Repeat("a", 32), strings.Repeat("b", 32), "1.0.0", 1, now)
	return s, d, v, now
}
func applicationSave(t *testing.T, s *Store, app, id, version string, code int, now time.Time) ApplicationVersion {
	t.Helper()
	ctx := context.Background()
	catalog, e := s.ApplicationCatalog(ctx)
	if e != nil {
		t.Fatal(e)
	}
	c := ApplicationChange{ID: id, ApplicationID: app, Revision: catalog.Revision, Definition: applications.Definition{Name: "Example app", Version: version, ProductCode: fmt.Sprintf("{%08X-0000-0000-0000-000000000000}", code), URL: "https://packages.example.invalid/application.msi", SHA256: strings.Repeat("a", 64)}}
	_, digest, e := s.ChangeApplication(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	v, _, e := s.ChangeApplication(ctx, c, "admin", digest, now)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func applicationQueue(t *testing.T, s *Store, c DeploymentChange, now time.Time) DeploymentReview {
	t.Helper()
	ctx := context.Background()
	r, e := s.DeployApplication(ctx, c, "admin", "", now, 120*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.DeployApplication(ctx, c, "admin", r.Digest, now, 120*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func applicationResult(t *testing.T, s *Store, d Device, id string, r applications.Report, now time.Time) {
	t.Helper()
	raw, _ := json.Marshal(r)
	zero := int32(0)
	if _, e := s.UpdateScriptRun(context.Background(), d.ID, d.Fingerprint, protocol.ScriptResult{ID: id, Outcome: "succeeded", ExitCode: &zero, Stdout: string(raw)}, now); e != nil {
		t.Fatal(e)
	}
}
func TestApplicationsImmutableAndLocallyApprovedRunnerBinding(t *testing.T) {
	s, _, v, now := applicationFixture(t)
	ctx := context.Background()
	if v.Mutation.Hash == v.Verification.Hash || v.Mutation.Definition.RunAs != "system" || v.Verification.Definition.RunAs != "restricted" {
		t.Fatal("execution identity binding")
	}
	if _, e := s.ScriptVersion(ctx, v.Mutation.ID); !errors.Is(e, ErrScript) {
		t.Fatal("managed mutation exposed as normal script", e)
	}
	visible, e := s.ScriptVersions(ctx, "")
	if e != nil || len(visible) != 1 {
		t.Fatal("managed runners polluted script library", e)
	}
	if _, e = s.CreateScriptVersion(ctx, ScriptVersion{ScriptVersion: protocol.ScriptVersion{ID: strings.Repeat("f", 32), ScriptID: v.Mutation.ScriptID, Definition: v.Mutation.Definition}, Actor: "admin"}, now); !errors.Is(e, ErrScript) {
		t.Fatal("managed code editable", e)
	}
	v2 := applicationSave(t, s, v.ApplicationID, strings.Repeat("c", 32), "2.0.0", 2, now.Add(time.Second))
	if v2.Number != 2 || v2.Mutation.Hash == v.Mutation.Hash {
		t.Fatal("version approval reused")
	}
	old, e := s.ApplicationVersion(ctx, v.ID)
	if e != nil || old.Definition != v.Definition || old.Mutation.Hash != v.Mutation.Hash {
		t.Fatal("old version changed", e)
	}
	catalog, _ := s.ApplicationCatalog(ctx)
	c := ApplicationChange{ID: strings.Repeat("9", 32), ApplicationID: v.ApplicationID, Revision: catalog.Revision, Definition: v.Definition}
	if _, _, e = s.ChangeApplication(ctx, c, "admin", "", now); !errors.Is(e, ErrApplication) {
		t.Fatal("product/version reuse allowed", e)
	}
	c.Definition = v2.Definition
	c.Definition.ProductCode = "{00000003-0000-0000-0000-000000000000}"
	c.Definition.Version = "3.0.0"
	_, digest, e := s.ChangeApplication(ctx, c, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	changed := c
	changed.Definition.SHA256 = strings.Repeat("b", 64)
	if _, _, e = s.ChangeApplication(ctx, changed, "admin", digest, now); !errors.Is(e, ErrApplication) {
		t.Fatal("definition review tampering", e)
	}
	if _, _, e = s.ChangeApplication(ctx, c, "admin", digest, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ChangeApplication(ctx, c, "admin", digest, now); !errors.Is(e, ErrApplication) {
		t.Fatal("definition replay", e)
	}
}
func TestApplicationBatchIsAtomicReviewedAndNeverRedelivered(t *testing.T) {
	s, d, v, now := applicationFixture(t)
	ctx := context.Background()
	other := Device{ID: strings.Repeat("8", 32), Hostname: "other", OS: "windows", Architecture: "amd64", Certificate: "test", Fingerprint: "other-fp"}
	if e := s.NewEnrollmentToken(ctx, "other", now, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := s.EnrollDevice(ctx, "other", other, now); e != nil {
		t.Fatal(e)
	}
	if e := s.RecordHeartbeat(ctx, other.ID, other.Fingerprint, protocol.Heartbeat{Hostname: other.Hostname, OS: other.OS, Architecture: other.Architecture, AgentVersion: "test"}, now); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "group-create", ID: "lab", Name: "Lab"}, now)
	for _, device := range []Device{d, other} {
		organizationApply(t, s, OrganizationChange{Action: "device", ID: device.ID, GroupID: "lab"}, now)
	}
	c := DeploymentChange{ID: strings.Repeat("1", 32), VersionID: v.ID, Operation: "verify", Groups: []string{"lab"}}
	r, e := s.DeployApplication(ctx, c, "admin", "", now, 120*time.Second)
	if e != nil || len(r.Targets) != 2 {
		t.Fatal("group review", e)
	}
	if _, e = s.DeployApplication(ctx, c, "admin", r.Digest, now, 120*time.Second); e == nil {
		t.Fatal("unsupported target accepted")
	}
	var n int
	if e = s.db.QueryRow("SELECT COUNT(*) FROM application_deployments").Scan(&n); e != nil || n != 0 {
		t.Fatal("partial batch", n, e)
	}
	if e = s.db.QueryRow("SELECT COUNT(*) FROM script_runs").Scan(&n); e != nil || n != 0 {
		t.Fatal("partial script queue", n, e)
	}
	raw, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "disabled"})
	if e = s.RecordScriptSupport(ctx, other.ID, other.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: other.ID}, now)
	if _, e = s.DeployApplication(ctx, c, "admin", r.Digest, now, 120*time.Second); !errors.Is(e, ErrApplication) {
		t.Fatal("group changed after review", e)
	}
	organizationApply(t, s, OrganizationChange{Action: "device", ID: other.ID, GroupID: "lab"}, now)
	r = applicationQueue(t, s, c, now)
	if _, e = s.DeployApplication(ctx, c, "admin", r.Digest, now, 120*time.Second); e != nil {
		t.Fatal("duplicate batch not idempotent", e)
	}
	if e = s.db.QueryRow("SELECT COUNT(*) FROM application_deployments").Scan(&n); e != nil || n != 2 {
		t.Fatal("duplicate intents", n, e)
	}
	if _, e = s.DispatchScriptRun(ctx, d.ID, "wrong", now); !errors.Is(e, ErrAuthentication) {
		t.Fatal("certificate bypass", e)
	}
	for _, device := range []Device{d, other} {
		q, e := s.DispatchScriptRun(ctx, device.ID, device.Fingerprint, now)
		if e != nil || q.Job == nil || q.Job.Version.Hash != v.Verification.Hash || q.Job.Version.Definition.RunAs != "restricted" {
			t.Fatal("wrong reviewed runner", e)
		}
		if again, e := s.DispatchScriptRun(ctx, device.ID, device.Fingerprint, now); e != nil || again.Job != nil {
			t.Fatal("redelivery", e)
		}
		applicationResult(t, s, device, q.Job.ID, applications.Report{Format: "msi_v1", Operation: "verify", Outcome: "verified", Reason: "verified", Observed: true, Products: []applications.Product{}}, now)
	}
	rows, e := s.ApplicationDeployments(ctx, Session{}, d.ID, now)
	if e != nil || len(rows) != 1 || rows[0].Status != "verified" || rows[0].Report == nil {
		t.Fatal("post verification missing", rows, e)
	}
	if _, e = s.db.Exec("DELETE FROM script_runs"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.ApplicationDeployments(ctx, Session{}, d.ID, now)
	if e != nil || rows[0].Status != "verified" || rows[0].RunID != nil {
		t.Fatal("bounded script pruning lost history", e)
	}
}
func TestApplicationUnknownAndPostconditionChecks(t *testing.T) {
	for _, mode := range []string{"false_success", "cancel_queued", "cancel_running", "expired", "lost_result", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			s, d, v, now := applicationFixture(t)
			ctx := context.Background()
			c := DeploymentChange{ID: strings.Repeat("1", 32), VersionID: v.ID, Operation: "install", Devices: []string{d.ID}}
			applicationQueue(t, s, c, now)
			id := applicationID(d.ID, c.ID)
			if mode == "cancel_queued" {
				if e := s.CancelApplicationDeployment(ctx, id, "admin", now); e != nil {
					t.Fatal(e)
				}
			} else if mode == "expired" {
				now = now.Add(2 * time.Minute)
			} else {
				q, e := s.DispatchScriptRun(ctx, d.ID, d.Fingerprint, now)
				if e != nil || q.Job == nil {
					t.Fatal(e)
				}
				switch mode {
				case "false_success":
					zero := int32(0)
					applicationResult(t, s, d, id, applications.Report{Format: "msi_v1", Operation: "install", Outcome: "verified", Reason: "verified", Observed: true, Products: []applications.Product{}, Mutated: true, InstallerExit: &zero}, now)
				case "cancel_running":
					if e = s.CancelApplicationDeployment(ctx, id, "admin", now); e != nil {
						t.Fatal(e)
					}
					if _, e = s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, scripting.Failure(id, "cancelled"), now); e != nil {
						t.Fatal(e)
					}
				case "lost_result":
					now = now.Add(6 * time.Minute)
				case "truncated":
					zero := int32(0)
					if _, e = s.UpdateScriptRun(ctx, d.ID, d.Fingerprint, protocol.ScriptResult{ID: id, Outcome: "succeeded", ExitCode: &zero, Truncated: true}, now); e != nil {
						t.Fatal(e)
					}
				}
			}
			rows, e := s.ApplicationDeployments(ctx, Session{}, d.ID, now)
			if e != nil || len(rows) != 1 {
				t.Fatal(e)
			}
			expected := "unknown"
			if mode == "cancel_queued" || mode == "expired" {
				expected = "cancelled"
			}
			if rows[0].Status != expected {
				t.Fatal("fabricated installation/rollback", rows[0])
			}
		})
	}
}
func TestApplicationPrivilegesScopeAndAuditRollback(t *testing.T) {
	s, d, v, now := applicationFixture(t)
	ctx := context.Background()
	tech := technicianFixture(t, s, now, TechnicianAccess{Devices: []string{d.ID}, Services: true})
	c := DeploymentChange{ID: strings.Repeat("1", 32), VersionID: v.ID, Operation: "verify", Devices: []string{d.ID}}
	if _, e := s.DeployApplication(ctx, c, tech.Actor(), "", now, 120*time.Second); !errors.Is(e, ErrForbidden) {
		t.Fatal("technician deployment bypass", e)
	}
	applicationQueue(t, s, c, now)
	rows, e := s.ApplicationDeployments(ctx, tech, "", now)
	if e != nil || len(rows) != 1 {
		t.Fatal("scope read", e)
	}
	if e = s.CancelApplicationDeployment(ctx, rows[0].ID, tech.Actor(), now); !errors.Is(e, ErrForbidden) {
		t.Fatal("technician canceled install", e)
	}
	if _, e = s.db.Exec("UPDATE technicians SET enabled=0"); e != nil {
		t.Fatal(e)
	}
	rows, e = s.ApplicationDeployments(ctx, tech, "", now)
	if e != nil || len(rows) != 0 {
		t.Fatal("disabled scope leak", e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER application_test_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	catalog, _ := s.ApplicationCatalog(ctx)
	change := ApplicationChange{ID: strings.Repeat("9", 32), ApplicationID: v.ApplicationID, Revision: catalog.Revision, Definition: v.Definition}
	change.Definition.ProductCode = "{00000002-0000-0000-0000-000000000000}"
	change.Definition.Version = "2.0.0"
	_, digest, e := s.ChangeApplication(ctx, change, "admin", "", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.ChangeApplication(ctx, change, "admin", digest, now); e == nil {
		t.Fatal("audit failure ignored")
	}
	after, _ := s.ApplicationCatalog(ctx)
	if len(after.Versions) != len(catalog.Versions) || after.Revision != catalog.Revision {
		t.Fatal("partial immutable version after rollback")
	}
}
func TestApplicationUpgradeVersionAndLocalOptIn(t *testing.T) {
	s, d, v1, now := applicationFixture(t)
	ctx := context.Background()
	v2 := applicationSave(t, s, v1.ApplicationID, strings.Repeat("c", 32), "2.0.0", 2, now)
	c := DeploymentChange{ID: strings.Repeat("1", 32), VersionID: v1.ID, PreviousVersionID: v2.ID, Operation: "update", Devices: []string{d.ID}}
	if _, e := s.DeployApplication(ctx, c, "admin", "", now, 120*time.Second); !errors.Is(e, ErrApplication) {
		t.Fatal("downgrade accepted", e)
	}
	c.VersionID = v2.ID
	c.PreviousVersionID = v1.ID
	raw, _ := json.Marshal(protocol.ScriptSupport{Restricted: true, Administrator: "disabled"})
	if e := s.RecordScriptSupport(ctx, d.ID, d.Fingerprint, protocol.FeatureReport{Capability: scripting.Capability, Status: "ok", Data: raw}, now); e != nil {
		t.Fatal(e)
	}
	r, e := s.DeployApplication(ctx, c, "admin", "", now, 120*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DeployApplication(ctx, c, "admin", r.Digest, now, 120*time.Second); e == nil {
		t.Fatal("missing local administrative opt-in bypassed")
	}
	c.Operation = "verify"
	c.PreviousVersionID = ""
	applicationQueue(t, s, c, now)
}
func TestApplicationMigrationPreservesExistingSchema20(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "data", "db")
	s, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := s.Info(ctx)
	rollbackApplicationSchema(t, s)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, _ := s.Info(ctx)
	if before != after {
		t.Fatal("application migration changed installation identity")
	}
}
