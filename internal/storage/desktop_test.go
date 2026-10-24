package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestDesktopAuthorizationTracksBrowserInactivityLogoutResetAndDevice(t *testing.T) {
	for _, change := range []string{"logout", "reset", "expiry", "inactive", "revoked", "other-owner", "other-device"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			s, e := Open(ctx, filepath.Join(t.TempDir(), "data", "db"))
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			now := time.Now()
			a := Administrator{Username: "admin", PasswordHash: "test", TOTPCipher: []byte("test")}
			if e = s.SetAdministrator(ctx, a, nil, false, now); e != nil {
				t.Fatal(e)
			}
			if e = s.ConfirmAdministrator(ctx, 1, 100, now); e != nil {
				t.Fatal(e)
			}
			v := Session{TokenHash: "desktop-test-owner", CSRF: "test", CreatedAt: now.Unix(), LastSeenAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
			if e = s.CompleteLogin(ctx, 1, 101, "", v, now); e != nil {
				t.Fatal(e)
			}
			d := Device{ID: "11111111111111111111111111111111", Hostname: "test", OS: "windows", Architecture: "amd64", Certificate: "test", Fingerprint: "test"}
			if e = s.NewEnrollmentToken(ctx, "test-token", now, now.Add(time.Minute)); e != nil {
				t.Fatal(e)
			}
			if e = s.EnrollDevice(ctx, "test-token", d, now); e != nil {
				t.Fatal(e)
			}
			if e = s.CheckDesktopAuthorization(ctx, d.ID, v.TokenHash, now); e != nil {
				t.Fatal("valid session", e)
			}
			if e = s.CheckDesktopAuthorization(ctx, d.ID, v.TokenHash, now.Add(20*time.Minute)); e != nil {
				t.Fatal(e)
			}
			var seen int64
			if e = s.db.QueryRow("SELECT last_seen_at FROM sessions WHERE token_hash=?", v.TokenHash).Scan(&seen); e != nil {
				t.Fatal(e)
			}
			if seen != now.Unix() {
				t.Fatal("agent poll refreshed browser inactivity")
			}
			switch change {
			case "logout":
				e = s.Logout(ctx, v.TokenHash, now)
			case "reset":
				e = s.SetAdministrator(ctx, a, nil, true, now)
			case "expiry":
				now = now.Add(time.Hour)
			case "inactive":
				now = now.Add(31 * time.Minute)
			case "revoked":
				e = s.RevokeDevice(ctx, d.ID, now)
			case "other-owner":
				v.TokenHash = "another"
			case "other-device":
				d.ID = "22222222222222222222222222222222"
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = s.CheckDesktopAuthorization(ctx, d.ID, v.TokenHash, now); e == nil {
				t.Fatal("authorization survived", change)
			}
		})
	}
}
