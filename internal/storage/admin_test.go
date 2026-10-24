package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticationFactorsConsumeAtomicallyAndResetRejectsStaleLogin(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%v", recovery), func(t *testing.T) {
			ctx := context.Background()
			store, err := Open(ctx, filepath.Join(t.TempDir(), "data", "server.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			now := time.Now().UTC()
			admin := Administrator{Username: "admin", PasswordHash: "test-hash", TOTPCipher: []byte("test-cipher")}
			if err := store.SetAdministrator(ctx, admin, []string{"test-recovery"}, false, now); err != nil {
				t.Fatal(err)
			}
			if err := store.ConfirmAdministrator(ctx, 1, 100, now); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			for index := 0; index < 2; index++ {
				go func(index int) {
					<-start
					factor := ""
					if recovery {
						factor = "test-recovery"
					}
					session := Session{TokenHash: fmt.Sprintf("session-%d", index), CSRF: "test-csrf", CreatedAt: now.Unix(), LastSeenAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
					results <- store.CompleteLogin(ctx, 1, 101, factor, session, now)
				}(index)
			}
			close(start)
			successes, rejections := 0, 0
			for index := 0; index < 2; index++ {
				err := <-results
				if err == nil {
					successes++
				} else if errors.Is(err, ErrAuthentication) {
					rejections++
				} else {
					t.Fatal(err)
				}
			}
			if successes != 1 || rejections != 1 {
				t.Fatal("concurrent factor consumption did not accept exactly one login")
			}
			if err := store.SetAdministrator(ctx, admin, []string{"new-recovery"}, true, now); err != nil {
				t.Fatal(err)
			}
			if err := store.ConfirmAdministrator(ctx, 2, 200, now); err != nil {
				t.Fatal(err)
			}
			stale := Session{TokenHash: "stale-session", CSRF: "test-csrf", CreatedAt: now.Unix(), LastSeenAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
			if err := store.CompleteLogin(ctx, 1, 201, "new-recovery", stale, now); !errors.Is(err, ErrAuthentication) {
				t.Fatal("login verified before reset bypassed credential-version check")
			}
			if err := store.CompleteLogin(ctx, 2, 201, "new-recovery", stale, now); err != nil {
				t.Fatal("rejected stale login consumed the replacement recovery code")
			}
		})
	}
}
