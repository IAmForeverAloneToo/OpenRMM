package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/logging"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/server"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const usage = `OpenRMM development server (administrator access and secure device enrollment)
Usage: openrmm-server [flags]
  -listen ADDRESS   Literal loopback IP:port (default 127.0.0.1:8443)
  -device-listen ADDRESS  Separate mTLS agent listener (default 127.0.0.1:8444)
  -alert-smtp-config PATH  Optional protected SMTP JSON file (email disabled by default)
  -offline-after DURATION  Offline threshold (default 120s; 3s to 24h)
  -device-authority PATH  Private device CA file (default .local/secrets/device-ca/authority.pem)
  -tls-cert PATH    Server certificate (default .local/tls/server.pem)
  -tls-key PATH     Private key (default .local/tls/server-key.pem)
  -database PATH    SQLite database (default .local/data/openrmm.db)
  -storage-info     Initialize/check storage, print local metadata, then exit
  -encryption-key PATH  MFA key file (default .local/secrets/admin-key.bin)
  -admin-setup      Local setup; JSON username/password on stdin
  -admin-confirm    Local MFA activation; JSON code on stdin
  -admin-reset      Local recovery; JSON username/password on stdin
  -admin-link       Print a one-time first-administrator setup link token (1 hour)
  -health           Check that the running server is ready, then exit
  -acme-domain NAME Automatic HTTPS certificate from Let's Encrypt for NAME
  -server-hosts LIST  Certificate from the server's own CA for these hosts (LAN)
  -public-url URL, -public-device-url URL  Installer addresses when none are set
  -container-network=true  Allow wildcard binding inside an isolated container
  -log-level LEVEL  debug, info, warn, error (default info)
  -help             Show usage
Environment overrides and setup: see README.md.
`

func run() int {
	c, err := config.LoadServer(os.Args[1:], os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(usage)
		return 0
	}
	if err != nil {
		logging.New(os.Stderr, slog.LevelInfo).Error("invalid server configuration", "reason", err.Error())
		return 2
	}
	logger := logging.New(os.Stderr, c.LogLevel)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if c.Health {
		if err := checkHealth(ctx, c); err != nil {
			logger.Error("server is not ready", "reason", err.Error())
			return 1
		}
		return 0
	}
	if c.AdminSetup || c.AdminConfirm || c.AdminReset || c.AdminLink {
		return runAdmin(ctx, c, logger)
	}
	if c.StorageInfo {
		storageCtx, cancelStorage := context.WithTimeout(ctx, 10*time.Second)
		defer cancelStorage()
		store, err := storage.Open(storageCtx, c.Database)
		if err != nil {
			logger.Error("storage inspection failed", "reason", err.Error())
			return 1
		}
		defer store.Close()
		info, err := store.Info(storageCtx)
		if err != nil {
			logger.Error("storage inspection failed", "reason", err.Error())
			return 1
		}
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			logger.Error("cannot write storage inspection result")
			return 1
		}
		return 0
	}
	if err := server.Run(ctx, c, logger); err != nil {
		logger.Error("server stopped", "reason", err.Error())
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
