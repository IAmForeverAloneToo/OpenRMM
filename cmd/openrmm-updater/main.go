// Command openrmm-updater is the server update sidecar. It is
// the only OpenRMM process with Docker access; it opens no network port and
// takes requests only from the exchange volume it shares with the server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/logging"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run() int {
	logger := logging.New(os.Stderr, slog.LevelInfo)
	if len(os.Args) > 1 {
		logger.Error("openrmm-updater takes no arguments; it is configured by the install command")
		return 2
	}
	project := env("OPENRMM_UPDATER_PROJECT", "")
	if project == "" {
		logger.Error("OPENRMM_UPDATER_PROJECT is required")
		return 2
	}
	exchange := env("OPENRMM_UPDATER_EXCHANGE", "/updater")
	if info, e := os.Stat(exchange); e != nil || !info.IsDir() {
		logger.Error("the exchange folder is missing")
		return 1
	}
	trust := serverupdate.Running(strings.Split(env("OPENRMM_UPDATER_KEYS", ""), ","))
	if len(trust.Keys) == 0 {
		logger.Warn("this build trusts no release key; updates will be refused")
	}
	db := env("OPENRMM_UPDATER_DATABASE", "openrmm.db")
	u := &serverupdate.Updater{
		Dir:     exchange,
		Engine:  serverupdate.NewDocker(env("OPENRMM_UPDATER_DOCKER_SOCKET", "/var/run/docker.sock")),
		Project: project,
		Service: env("OPENRMM_UPDATER_SERVICE", "server"),
		Trust:   trust,
		Backups: serverupdate.Backups{
			Dir:     env("OPENRMM_UPDATER_BACKUPS", "/backups"),
			Sources: map[string]string{"data": env("OPENRMM_UPDATER_DATA", "/data"), "secrets": env("OPENRMM_UPDATER_SECRETS", "/secrets")},
			DB:      db,
			Keep:    3,
			CheckDB: func(path string) error {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				return storage.CheckFile(ctx, path)
			},
		},
		Logf: func(msg string, args ...any) { logger.Info(msg, args...) },
	}
	for _, d := range []string{u.Backups.Dir, u.Backups.Sources["data"], u.Backups.Sources["secrets"]} {
		if info, e := os.Stat(d); e != nil || !info.IsDir() {
			logger.Error("a required folder is missing", "folder", d)
			return 1
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	logger.Info("updater started", "version", trust.Version, "sequence", trust.Sequence)
	u.Run(ctx)
	if errors.Is(ctx.Err(), context.Canceled) {
		return 0
	}
	return 1
}

func main() { os.Exit(run()) }
