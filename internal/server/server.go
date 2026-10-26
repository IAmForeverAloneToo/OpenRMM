// Package server owns HTTP routing and the server lifecycle.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/acmecert"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/alerting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/auth"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/lancert"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/serverupdate"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
)

func Handler(store *storage.Store, administrator *auth.Service, deviceService *devices.Service) http.Handler {
	return handler(store, administrator, deviceService, &serverUpdates{current: serverupdate.Running(nil)}, nil)
}

func handler(store *storage.Store, administrator *auth.Service, deviceService *devices.Service, updates *serverUpdates, mail *mailSource) http.Handler {
	if mail == nil {
		mail = &mailSource{store: store, auth: administrator}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if store == nil || store.Ready(ctx) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("{\"status\":\"unavailable\"}\n"))
			return
		}
		_, _ = w.Write([]byte("{\"status\":\"ok\"}\n"))
	})
	if administrator != nil {
		registerAPI(mux, &api{auth: administrator, store: store, devices: deviceService, updates: updates, mail: mail})
	}
	if deviceService != nil {
		registerEnrollment(mux, deviceService)
	}
	registerUI(mux)
	return secureWeb(mux)
}

// Run serves TLS only and closes the listener on cancellation.
func Run(ctx context.Context, c config.Server, logger *slog.Logger) error {
	// The dashboard's certificate: from an ACME CA, the server's own CA or
	// the files.
	var certificates *acmecert.Manager
	var own *lancert.Manager
	var certificate tls.Certificate
	var err error
	if len(c.ServerHosts) > 0 {
		own = &lancert.Manager{Dir: c.ServerCADir, Hosts: c.ServerHosts}
		if err = own.Ensure(); err != nil {
			return fmt.Errorf("cannot prepare the server certificate: %w", err)
		}
		ownCtx, stopOwn := context.WithCancel(ctx)
		ownDone := make(chan struct{})
		go func() {
			defer close(ownDone)
			own.Run(ownCtx, func(msg string, args ...any) { logger.Warn(msg, args...) })
		}()
		defer func() { stopOwn(); <-ownDone }()
	} else if c.ACMEDomain != "" {
		certificates = &acmecert.Manager{Domain: c.ACMEDomain, Email: c.ACMEEmail, Directory: c.ACMEDirectory, Cache: c.ACMECache}
		acmeCtx, stopACME := context.WithCancel(ctx)
		acmeDone := make(chan struct{})
		go func() {
			defer close(acmeDone)
			certificates.Run(acmeCtx, func(msg string, args ...any) { logger.Info(msg, args...) })
		}()
		defer func() { stopACME(); <-acmeDone }()
	} else if certificate, err = tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		return errors.New("cannot load server TLS certificate/key; run the development certificate helper or check TLS configuration")
	}
	// Installers carry this CA; fail at start-up, not at download.
	if _, err := readInstallerCA(c.CAFile); err != nil {
		return errors.New("the TLS CA file (-tls-ca) is unreadable or not a CA certificate bundle")
	}
	startupCtx, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	store, err := storage.Open(startupCtx, c.Database)
	if err != nil {
		cancelStartup()
		return err
	}
	defer store.Close()
	// Alert e-mail: the protected SMTP file when given, otherwise the
	// dashboard's settings.
	fileMailer, err := alerting.LoadMailer(c.AlertSMTPConfig)
	if err != nil {
		cancelStartup()
		return err
	}
	mail := &mailSource{store: store, file: fileMailer}
	mailID := ""
	if fileMailer != nil {
		mailID = fileMailer.ID
	} else if mailID, err = storedMailID(startupCtx, store); err != nil {
		cancelStartup()
		return errors.New("cannot read the e-mail settings")
	}
	offline := c.OfflineAfter
	if offline <= 0 {
		offline = 120 * time.Second
	}
	if err = store.InitializeAlerts(startupCtx, offline, mailID, time.Now()); err != nil {
		cancelStartup()
		return errors.New("cannot initialize alerts")
	}
	if err = store.InitializeScriptSchedules(startupCtx, time.Now()); err != nil {
		cancelStartup()
		return errors.New("cannot initialize script schedules")
	}
	if err = store.InitializePatchPolicies(startupCtx, time.Now()); err != nil {
		cancelStartup()
		return errors.New("cannot initialize patch policies")
	}
	if c.PublicURL != "" {
		if e := store.InitializeInstallerSettings(startupCtx, storage.InstallerSettings{ServerURL: c.PublicURL, DeviceURL: c.PublicDeviceURL}, time.Now()); e != nil {
			logger.Warn("the installer addresses could not be stored; set them on the Deploy page")
		}
	}
	importBundledRelease(ctx, store, logger)
	if err = store.UseEvidence(c.EvidenceDir, c.EvidenceQuota); err != nil {
		cancelStartup()
		return err
	}
	if e := store.FinishTranscripts(startupCtx, time.Now()); e != nil {
		logger.Warn("terminal transcripts left by the last stop could not all be stored; retrying at the next start")
	}
	evidenceCtx, stopEvidence := context.WithCancel(ctx)
	evidenceDone := make(chan struct{})
	go func() { defer close(evidenceDone); runEvidenceVerifier(evidenceCtx, store, logger) }()
	defer func() { stopEvidence(); <-evidenceDone }()
	patchCtx, stopPatches := context.WithCancel(ctx)
	patchDone := make(chan struct{})
	go func() { defer close(patchDone); runPatchScheduler(patchCtx, store, offline, logger) }()
	defer func() { stopPatches(); <-patchDone }()
	ringsCtx, stopRings := context.WithCancel(ctx)
	ringsDone := make(chan struct{})
	go func() { defer close(ringsDone); runAgentRings(ringsCtx, store, offline, logger) }()
	defer func() { stopRings(); <-ringsDone }()
	scheduleCtx, stopSchedules := context.WithCancel(ctx)
	scheduleDone := make(chan struct{})
	go func() { defer close(scheduleDone); runScriptScheduler(scheduleCtx, store, offline, logger) }()
	defer func() { stopSchedules(); <-scheduleDone }()
	alertCtx, stopAlerts := context.WithCancel(ctx)
	evalDone, mailDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(evalDone); runAlertEvaluator(alertCtx, store, logger) }()
	go func() { defer close(mailDone); runAlertMail(alertCtx, store, mail.Current, logger) }()
	defer func() { stopAlerts(); <-evalDone; <-mailDone }()

	housekeepingCtx, stopHousekeeping := context.WithCancel(ctx)
	housekeepingDone := make(chan struct{})
	go func() {
		defer close(housekeepingDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if e := store.SweepFiles(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("file transfer retention cleanup unavailable")
			}
			if e := store.SweepEvidence(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("evidence collection cleanup unavailable")
			}
			if e := store.FinishTranscripts(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("a terminal transcript could not be stored; retrying")
			}
			if e := store.PruneScriptRuns(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("script history retention cleanup unavailable")
			}
			if e := store.PruneScriptBatches(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("script batch history retention cleanup unavailable")
			}
			if e := store.PruneSessionHistory(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("session history retention cleanup unavailable")
			}
			if e := store.PruneLogonHistory(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("logon history retention cleanup unavailable")
			}
			if e := store.PruneSoftwareHistory(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("software history retention cleanup unavailable")
			}
			if e := store.PruneMetrics(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("metric history retention cleanup unavailable")
			}
			if e := store.PruneUpdateJobs(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("update job retention cleanup unavailable")
			}
			if e := store.PruneEventQueries(housekeepingCtx, time.Now()); e != nil && housekeepingCtx.Err() == nil {
				logger.Warn("event query retention cleanup unavailable")
			}
			select {
			case <-housekeepingCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { stopHousekeeping(); <-housekeepingDone }()

	administrator, err := auth.New(startupCtx, store, c.EncryptionKey)
	if err != nil {
		cancelStartup()
		return err
	}
	mail.auth = administrator
	if e := mail.Reload(startupCtx, time.Now()); e != nil {
		logger.Warn("alert e-mail is off: the dashboard's e-mail settings cannot be used; check them on the Alerts settings page")
	}
	authorityPath := c.DeviceAuthority
	if authorityPath == "" {
		authorityPath = filepath.Join(filepath.Dir(c.EncryptionKey), "device-ca", "authority.pem")
	}
	deviceService, err := devices.New(startupCtx, store, authorityPath)
	if deviceService != nil {
		deviceService.OfflineAfter = c.OfflineAfter
		deviceService.InstallerCA = c.CAFile
		if _, port, e := net.SplitHostPort(c.DeviceListen); e == nil {
			deviceService.DevicePort, _ = strconv.Atoi(port)
		}
		desktopCtx, stopDesktop := context.WithCancel(ctx)
		defer func() {
			stopDesktop()
			closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			deviceService.Desktop.Close(closeCtx)
			deviceService.Terminal.Close(closeCtx)
		}()
		go deviceService.Desktop.Run(desktopCtx)
		go deviceService.Terminal.Run(desktopCtx)
	}
	cancelStartup()
	if err != nil {
		return err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Listen)
	if err != nil {
		return errors.New("cannot bind server listener; check the listen address and whether the port is occupied")
	}
	defer listener.Close()
	makeServer := func(handler http.Handler, tlsConfig *tls.Config) *http.Server {
		return &http.Server{
			Handler:           handler,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 * 1024,
			// TLS parse errors may include untrusted peer input; omit default raw logging.
			ErrorLog: log.New(io.Discard, "", 0),
		}
	}
	dashboardTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	deviceTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: deviceService.Roots()}
	if certificates != nil {
		// Agents verify the same publicly trusted certificate on their port.
		dashboardTLS = certificates.TLSConfig()
		deviceTLS.Certificates, deviceTLS.GetCertificate = nil, certificates.GetCertificate
	}
	if own != nil {
		dashboardTLS.Certificates, dashboardTLS.GetCertificate = nil, own.GetCertificate
		deviceTLS.Certificates, deviceTLS.GetCertificate = nil, own.GetCertificate
	}
	// Daily release check and updates through the sidecar.
	updates := &serverUpdates{dir: c.UpdaterDir, current: serverupdate.Running(c.ReleaseKeys), checker: serverupdate.Checker{Client: &http.Client{Timeout: 30 * time.Second}}}
	if e := updates.writeBackupSchedule(ctx, store); e != nil {
		logger.Warn("the backup schedule could not be handed to the updater; it keeps its previous schedule")
	}
	updatesCtx, stopUpdates := context.WithCancel(ctx)
	updatesDone := make(chan struct{})
	go func() { defer close(updatesDone); runServerUpdates(updatesCtx, store, updates, logger) }()
	defer func() { stopUpdates(); <-updatesDone }()
	dashboard := handler(store, administrator, deviceService, updates, mail)
	if certificates != nil {
		// A public name with a trusted certificate: browsers should never try
		// plain HTTP for it.
		dashboard = strictTransport(dashboard)
	}
	s := makeServer(dashboard, dashboardTLS)
	servers := []*http.Server{s}
	var deviceListener net.Listener
	if c.DeviceListen != "" {
		deviceListener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", c.DeviceListen)
		if err != nil {
			return errors.New("cannot bind device listener; check device-listen and whether its port is occupied")
		}
		defer deviceListener.Close()
		servers = append(servers, makeServer(DeviceHandler(deviceService), deviceTLS))
		servers[len(servers)-1].IdleTimeout = 90 * time.Second
	}
	finished := make(chan error, len(servers))
	go func() { finished <- s.ServeTLS(listener, "", "") }()
	if deviceListener != nil {
		go func() { finished <- servers[1].ServeTLS(deviceListener, "", "") }()
		logger.Info("device listener started", "listen", deviceListener.Addr().String())
	}
	mode := "local-development"
	if certificates != nil {
		mode = "acme " + c.ACMEDomain
	} else if own != nil {
		mode = "server-ca"
	}
	logger.Info("server started", "listen", listener.Addr().String(), "mode", mode)
	select {
	case err := <-finished:
		for _, server := range servers {
			_ = server.Close()
		}
		for index := 1; index < len(servers); index++ {
			<-finished
		}
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("server listener stopped unexpectedly")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var shutdownErr error
		for _, server := range servers {
			if err := server.Shutdown(shutdownCtx); err != nil {
				shutdownErr = err
				_ = server.Close()
			}
		}
		for range servers {
			<-finished
		}
		if shutdownErr != nil {
			return errors.New("server could not finish active requests before shutdown")
		}
		logger.Info("server stopped")
		return nil
	}
}
