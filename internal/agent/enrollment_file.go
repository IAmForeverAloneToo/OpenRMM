package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/IAmForeverAloneToo/OpenRMM/internal/config"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/privatefs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
)

// An installed service without an identity enrolls itself with
// the enrollment.json that the downloaded installer placed in its data folder,
// then deletes the file. A service that already has an identity never enrolls
// again; it only removes a leftover file.

// deviceRecord is device.json next to the state folder: the enrolled device's
// ID and server, readable by administrators (the state folder is SYSTEM-only).
// The downloaded installer uses it to tell that the machine is enrolled.
type deviceRecord struct {
	DeviceID  string `json:"device_id"`
	DeviceURL string `json:"device_url"`
}

// recordDevice writes device.json for the saved identity when it changed.
func recordDevice(c config.Agent, logger *slog.Logger) {
	value, _, _, err := loadCredentials(c.State)
	if err != nil {
		return
	}
	b, _ := json.Marshal(deviceRecord{DeviceID: value.Credential.DeviceID, DeviceURL: value.DeviceURL})
	path := filepath.Join(filepath.Dir(c.State), "device.json")
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, b) {
		return
	}
	temp := path + ".tmp"
	if os.WriteFile(temp, b, 0644) != nil || os.Rename(temp, path) != nil {
		_ = os.Remove(temp)
		logger.Warn("cannot record the device identity in device.json")
	}
}

func enrollmentFilePath(c config.Agent) string {
	return filepath.Join(filepath.Dir(c.State), "enrollment.json")
}

func readEnrollmentFile(path string) (protocol.EnrollmentFile, error) {
	invalid := errors.New("the installer enrollment file is invalid; download a new installer")
	b, err := readLimited(path, 65536)
	if err != nil {
		return protocol.EnrollmentFile{}, err
	}
	var f protocol.EnrollmentFile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || !errors.Is(d.Decode(new(any)), io.EOF) || f.Version != 1 || len(f.Token) != 43 {
		return protocol.EnrollmentFile{}, invalid
	}
	server, ok1 := protocol.HTTPSOrigin(f.ServerURL)
	device, ok2 := protocol.HTTPSOrigin(f.DeviceURL)
	if !ok1 || !ok2 {
		return protocol.EnrollmentFile{}, invalid
	}
	if _, err := trust(f.ServerCA); err != nil {
		return protocol.EnrollmentFile{}, invalid
	}
	f.ServerURL, f.DeviceURL = server, device
	return f, nil
}

// enrollFromFile returns once the service has an identity, or at once when it
// has neither an identity nor an enrollment file (Run then reports that).
// Failures are retried: every minute, or every 15 minutes when the server
// rejects the token, until the file is replaced or the service stops.
func enrollFromFile(ctx context.Context, c config.Agent, logger *slog.Logger) error {
	path := enrollmentFilePath(c)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(c.State, "credentials.json")); err == nil {
		if os.Remove(path) == nil {
			logger.Warn("removed an installer enrollment file; this device is already enrolled")
		}
		return nil
	}
	// The file holds the token: keep the data folder SYSTEM and Administrators only.
	if c.Service {
		if err := privatefs.RestrictInstallation(filepath.Dir(c.State)); err != nil {
			logger.Error("cannot restrict the agent data folder; continuing")
		}
	}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		return errors.New("enrollment currently supports Windows x64")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return errors.New("cannot read device hostname")
	}
	for {
		wait := time.Minute
		f, err := readEnrollmentFile(path)
		if err == nil {
			enrolling := c
			enrolling.ServerURL, enrolling.DeviceURL = f.ServerURL, f.DeviceURL
			var id string
			if id, err = enrollWith(ctx, enrolling, f.Token, []byte(f.ServerCA), hostname, "windows", "amd64", true); err == nil {
				if os.Remove(path) != nil {
					logger.Warn("cannot remove the installer enrollment file after enrolling")
				}
				logger.Info("device enrolled with the installer's enrollment file", "device_id", id, "server", f.ServerURL)
				return nil
			}
		}
		if errors.Is(err, ErrDeviceRejected) || errors.Is(err, ErrRequestRejected) {
			wait = 15 * time.Minute
		}
		logger.Error("enrollment with the installer's enrollment file failed; retrying", "reason", err.Error(), "retry_in", wait.String())
		if !waitContext(ctx, wait) {
			return ctx.Err()
		}
	}
}
