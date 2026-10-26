// Command openrmm-updater is the server update and backup sidecar. It is
// the only OpenRMM process with Docker access; it opens no network port and
// takes requests only from the exchange volume it shares with the server.
//
// The install command also runs it in a one-off container for backups and
// restores (see "openrmm-updater help").
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/logging"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

const usage = `Usage: openrmm-updater [command]
  (none)                 run as the update and backup sidecar
  backup                 take a backup now while the server runs; prints its name
  list                   list the backups
  export NAME            write a backup as .tar.gz to standard output
  import                 read a backup .tar.gz from standard input; prints its name
  restore NAME [--revocations-stdin] [--skip-safety-backup]
                         restore a backup while the server is stopped
  export-evidence [--since UNIX]
                         write stored evidence (changed since a time) as .tar to standard output
  import-evidence        add evidence from a .tar on standard input
`

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func backups() serverupdate.Backups {
	return serverupdate.Backups{
		Dir:     env("OPENRMM_UPDATER_BACKUPS", "/backups"),
		Sources: map[string]string{"data": env("OPENRMM_UPDATER_DATA", "/data"), "secrets": env("OPENRMM_UPDATER_SECRETS", "/secrets")},
		DB:      env("OPENRMM_UPDATER_DATABASE", "openrmm.db"),
		CheckDB: func(path string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			return storage.CheckFile(ctx, path)
		},
		Snapshot: func(src, dst string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			return storage.SnapshotFile(ctx, src, dst)
		},
		Inspect: func(path string) (string, int, error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			info, e := storage.InspectFile(ctx, path)
			return info.InstanceID, info.SchemaVersion, e
		},
	}
}

func folders(logger *slog.Logger, dirs ...string) bool {
	for _, d := range dirs {
		if info, e := os.Stat(d); e != nil || !info.IsDir() {
			logger.Error("a required folder is missing", "folder", d)
			return false
		}
	}
	return true
}

func sidecar(logger *slog.Logger) int {
	project := env("OPENRMM_UPDATER_PROJECT", "")
	if project == "" {
		logger.Error("OPENRMM_UPDATER_PROJECT is required")
		return 2
	}
	exchange := env("OPENRMM_UPDATER_EXCHANGE", "/updater")
	trust := serverupdate.Running(strings.Split(env("OPENRMM_UPDATER_KEYS", ""), ","))
	if len(trust.Keys) == 0 {
		logger.Warn("this build trusts no release key; updates will be refused")
	}
	u := &serverupdate.Updater{
		Dir:     exchange,
		Engine:  serverupdate.NewDocker(env("OPENRMM_UPDATER_DOCKER_SOCKET", "/var/run/docker.sock")),
		Project: project,
		Service: env("OPENRMM_UPDATER_SERVICE", "server"),
		Trust:   trust,
		Backups: backups(),
		Logf:    func(msg string, args ...any) { logger.Info(msg, args...) },
	}
	if !folders(logger, exchange, u.Backups.Dir, u.Backups.Sources["data"], u.Backups.Sources["secrets"]) {
		return 1
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

// command runs one backup command; messages for the operator go to standard
// error, data to standard output.
func command(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	b := backups()
	if len(args) == 0 {
		return errors.New("no command")
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "backup":
		if len(args) != 1 {
			return errors.New("backup takes no arguments")
		}
		name := serverupdate.NewBackupName("manual", time.Now())
		if e := b.CreateLive(name); e != nil {
			return fmt.Errorf("the backup failed: %w", e)
		}
		_ = b.Prune()
		fmt.Fprintln(stdout, name)
		return nil
	case "list":
		list, e := b.List()
		if e != nil {
			return errors.New("cannot read the backups")
		}
		for _, x := range list {
			fmt.Fprintf(stdout, "%-30s %s  %8.1f MB\n", x.Name, time.Unix(x.CreatedAt, 0).UTC().Format("2006-01-02 15:04 UTC"), float64(x.Size)/1e6)
		}
		return nil
	case "export":
		if len(args) != 2 {
			return errors.New("export needs a backup name")
		}
		return b.Export(args[1], stdout)
	case "import":
		name, e := b.Import(stdin)
		if e != nil {
			return e
		}
		fmt.Fprintln(stdout, name)
		return nil
	case "restore":
		if len(args) < 2 {
			return errors.New("restore needs a backup name")
		}
		o := serverupdate.RestoreOptions{
			Now:     time.Now(),
			Revoked: func(db string) (map[string]int64, error) { return storage.RevokedDevicesFile(context.Background(), db) },
			Reconcile: func(db string, revoked map[string]int64) error {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
				defer cancel()
				return storage.ReconcileRestore(ctx, db, revoked, time.Now())
			},
		}
		for _, a := range args[2:] {
			switch a {
			case "--skip-safety-backup":
				o.SkipSafety = true
			case "--revocations-stdin":
				var r serverupdate.Revocations
				d := json.NewDecoder(io.LimitReader(stdin, 16<<20))
				d.DisallowUnknownFields()
				if d.Decode(&r) != nil {
					return errors.New("the revocation list could not be read")
				}
				o.Revocations = &r
			default:
				return fmt.Errorf("unknown option %s", a)
			}
		}
		result, e := b.RestoreSafely(args[1], o)
		if e != nil {
			return e
		}
		if result.Safety != "" {
			fmt.Fprintf(stderr, "The replaced state was kept as backup %s.\n", result.Safety)
		}
		fmt.Fprintf(stderr, "Restored %s; %d revoked devices carried over.\n", args[1], result.Carried)
		return nil
	case "export-evidence":
		var since int64
		if len(args) == 3 && args[1] == "--since" {
			n, e := strconv.ParseInt(args[2], 10, 64)
			if e != nil || n < 0 {
				return errors.New("--since needs a Unix time")
			}
			since = n
		} else if len(args) != 1 {
			return errors.New("usage: export-evidence [--since UNIX]")
		}
		n, e := serverupdate.ExportEvidence(env("OPENRMM_UPDATER_EVIDENCE", "/evidence"), since, stdout)
		if e != nil {
			return fmt.Errorf("the evidence export failed: %w", e)
		}
		fmt.Fprintf(stderr, "%d evidence files exported.\n", n)
		return nil
	case "import-evidence":
		added, skipped, e := serverupdate.ImportEvidence(env("OPENRMM_UPDATER_EVIDENCE", "/evidence"), stdin)
		fmt.Fprintf(stderr, "%d evidence files added, %d already present.\n", added, skipped)
		return e
	}
	return fmt.Errorf("unknown command %s (see help)", args[0])
}

func run() int {
	logger := logging.New(os.Stderr, slog.LevelInfo)
	// The containers have a read-only root file system; SQLite's temporary
	// files (large sorts while copying or checking a database) go to the
	// backup volume instead of /tmp.
	if os.Getenv("SQLITE_TMPDIR") == "" {
		_ = os.Setenv("SQLITE_TMPDIR", env("OPENRMM_UPDATER_BACKUPS", "/backups"))
	}
	if len(os.Args) == 1 {
		return sidecar(logger)
	}
	if e := command(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); e != nil {
		fmt.Fprintf(os.Stderr, "openrmm-updater: %v\n", e)
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
