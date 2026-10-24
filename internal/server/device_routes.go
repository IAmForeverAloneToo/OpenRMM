package server

import (
	"encoding/json"
	"errors"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/desktop"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/devices"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/eventlogs"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/features"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/filetransfer"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/protocol"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/scripting"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/storage"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/terminal"
	"github.com/IAmForeverAloneToo/OpenRMM/internal/windowsupdate"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"
)

func deviceAuthenticationError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrAuthentication) {
		if errors.Is(err, storage.ErrDeviceRevoked) {
			w.Header().Set(protocol.DeviceStatusHeader, "revoked")
		}
		http.Error(w, "Device authentication failed.", 403)
	} else {
		http.Error(w, "Device authentication is temporarily unavailable.", 503)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	return readJSONLimit(w, r, value, 8192)
}

func readJSONLimit(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	typeName, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typeName != "application/json" {
		http.Error(w, "Use JSON.", 415)
		return false
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Query parameters are not accepted.", 400)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		var tooLarge *http.MaxBytesError
		status := 400
		if errors.As(err, &tooLarge) {
			status = 413
		}
		http.Error(w, "Invalid request.", status)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		http.Error(w, "Invalid request.", 400)
		return false
	}
	return true
}

func registerEnrollment(mux *http.ServeMux, service *devices.Service) {
	mux.HandleFunc("POST /api/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var request protocol.Enrollment
		if !readJSON(w, r, &request) {
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = "unknown"
		}
		credential, err := service.Enroll(r.Context(), request, peer)
		if err != nil {
			switch {
			case errors.Is(err, devices.ErrLimited):
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too many enrollment attempts.", 429)
			case errors.Is(err, storage.ErrAuthentication):
				http.Error(w, "Enrollment failed. Check the token and request a fresh token if necessary.", 401)
			default:
				http.Error(w, "Enrollment is temporarily unavailable.", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(credential)
	})
}

func DeviceHandler(service *devices.Service) http.Handler {
	// File traffic uses the same certificate-only listener and bounded decoder.
	mux := http.NewServeMux()
	registerFileDevice(mux, service)
	registerEvidenceDevice(mux, service)
	registerAgentUpdateDevice(mux, service)
	registerDesktopDevice(mux, service)
	registerTerminalDevice(mux, service)

	mux.HandleFunc("POST /api/v1/agent/scripts/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.PollScriptRun(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/scripts/result", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input protocol.ScriptResult
		if !readJSONLimit(w, r, &input, scripting.MaxBytes) {
			return
		}
		v, e := service.ScriptRunResult(r.Context(), r.TLS, input)
		if e != nil {
			if errors.Is(e, storage.ErrScript) {
				http.Error(w, "Invalid or expired script result.", 400)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/updates/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.PollUpdateJob(r.Context(), r.TLS)
		if e != nil {
			if errors.Is(e, storage.ErrUpdateJob) {
				http.Error(w, "Update job unavailable.", 409)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/updates/progress", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input protocol.UpdateProgress
		if !readJSONLimit(w, r, &input, windowsupdate.MaxBytes) {
			return
		}
		v, e := service.UpdateJobProgress(r.Context(), r.TLS, input)
		if e != nil {
			if errors.Is(e, storage.ErrUpdateJob) {
				http.Error(w, "Invalid or expired update progress.", 400)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/event-logs/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.PollEventQuery(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/event-logs/result", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input protocol.EventResult
		if !readJSONLimit(w, r, &input, eventlogs.MaxResultBytes) {
			return
		}
		v, e := service.EventQueryResult(r.Context(), r.TLS, input)
		if e != nil {
			if errors.Is(e, storage.ErrEventQuery) {
				http.Error(w, "Invalid or expired event result.", 400)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/process-actions/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.PollProcessAction(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/process-actions/result", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input protocol.ProcessResult
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.ProcessActionResult(r.Context(), r.TLS, input)
		if e != nil {
			if errors.Is(e, storage.ErrProcessAction) {
				http.Error(w, "Invalid or expired result.", 400)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/service-actions/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input struct{}
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.PollServiceAction(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/service-actions/result", func(w http.ResponseWriter, r *http.Request) {
		if _, e := service.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var input protocol.ServiceResult
		if !readJSON(w, r, &input) {
			return
		}
		v, e := service.ServiceActionResult(r.Context(), r.TLS, input)
		if e != nil {
			if errors.Is(e, storage.ErrAction) {
				http.Error(w, "Invalid or expired result.", 400)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/features", func(w http.ResponseWriter, r *http.Request) {
		if _, err := service.Authenticate(r.Context(), r.TLS); err != nil {
			deviceAuthenticationError(w, err)
			return
		}
		var report protocol.FeatureReport
		if !readJSONLimit(w, r, &report, 2*1024*1024+4096) {
			return
		}
		receipt, err := service.Feature(r.Context(), r.TLS, report)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrAuthentication):
				deviceAuthenticationError(w, err)
			case errors.Is(err, features.ErrReport):
				http.Error(w, "Invalid or unknown feature report.", 400)
			default:
				http.Error(w, "Feature reporting is temporarily unavailable.", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
	mux.HandleFunc("POST /api/v1/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if _, err := service.Authenticate(r.Context(), r.TLS); err != nil {
			deviceAuthenticationError(w, err)
			return
		}
		var input protocol.Heartbeat
		if !readJSON(w, r, &input) {
			return
		}
		receipt, err := service.Heartbeat(r.Context(), r.TLS, input)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrAuthentication):
				deviceAuthenticationError(w, err)
			case errors.Is(err, devices.ErrInvalidHeartbeat):
				http.Error(w, "Invalid heartbeat metadata.", 400)
			default:
				http.Error(w, "Heartbeat is temporarily unavailable.", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
	mux.HandleFunc("GET /api/v1/agent/identity", func(w http.ResponseWriter, r *http.Request) {
		d, err := service.Authenticate(r.Context(), r.TLS)
		if err != nil {
			deviceAuthenticationError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.Identity{DeviceID: d.ID})
	})
	mux.HandleFunc("POST /api/v1/agent/renew", func(w http.ResponseWriter, r *http.Request) {
		if _, err := service.Authenticate(r.Context(), r.TLS); err != nil {
			deviceAuthenticationError(w, err)
			return
		}
		var request protocol.Renewal
		if !readJSON(w, r, &request) {
			return
		}
		credential, err := service.Renew(r.Context(), r.TLS, request)
		if err != nil {
			if errors.Is(err, storage.ErrAuthentication) {
				deviceAuthenticationError(w, err)
			} else {
				http.Error(w, "Renewal is temporarily unavailable.", 503)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(credential)
	})
	return secureWeb(mux)
}

var fileSlots = make(chan struct{}, 2)

func boundedFile(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case fileSlots <- struct{}{}:
			defer func() { <-fileSlots }()
			next(w, r)
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "File transfer busy; retry shortly.", 429)
		}
	}
}

func registerFileDevice(mux *http.ServeMux, s *devices.Service) {
	mux.HandleFunc("POST /api/v1/agent/files/poll", boundedFile(func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		v, e := s.PollFile(r.Context(), r.TLS)
		if e != nil {
			if errors.Is(e, storage.ErrFile) {
				http.Error(w, "File work unavailable.", 409)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}))
	mux.HandleFunc("POST /api/v1/agent/files/result", boundedFile(func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var in protocol.FileResult
		if !readJSONLimit(w, r, &in, filetransfer.MaxWire) {
			return
		}
		v, e := s.FileResult(r.Context(), r.TLS, in)
		if e != nil {
			if errors.Is(e, storage.ErrFile) {
				http.Error(w, "Invalid or expired file result.", 409)
			} else {
				deviceAuthenticationError(w, e)
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}))
}

// Evidence uploads have their own slots and per-request deadlines:
// an 8 MiB chunk over a slow link outlasts the listener's 10 s defaults.
// Polls are cheap and stay outside the slots.
var evidenceSlots = make(chan struct{}, 8)

// payloadSlots bounds drop downloads separately, so long
// downloads never hold the slots evidence uploads need.
var payloadSlots = make(chan struct{}, 4)

func registerEvidenceDevice(mux *http.ServeMux, s *devices.Service) {
	bounded := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			select {
			case evidenceSlots <- struct{}{}:
				defer func() { <-evidenceSlots }()
				next(w, r)
			default:
				w.Header().Set("Retry-After", "5")
				http.Error(w, "Evidence upload busy; retry shortly.", 429)
			}
		}
	}
	fail := func(w http.ResponseWriter, e error) {
		if errors.Is(e, storage.ErrEvidence) {
			http.Error(w, "Invalid, finished or refused evidence job.", 409)
		} else {
			deviceAuthenticationError(w, e)
		}
	}
	job := func(r *http.Request) (string, bool) {
		id := r.PathValue("job")
		return id, protocol.ValidID(id)
	}
	mux.HandleFunc("POST /api/v1/agent/evidence/poll", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		v, e := s.PollEvidence(r.Context(), r.TLS)
		if e != nil {
			fail(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/evidence/{job}/start", bounded(func(w http.ResponseWriter, r *http.Request) {
		id, ok := job(r)
		var in protocol.EvidenceStart
		if !ok || !readJSON(w, r, &in) {
			if !ok {
				http.Error(w, "Unknown job.", 404)
			}
			return
		}
		v, e := s.StartEvidence(r.Context(), r.TLS, id, in)
		if e != nil {
			fail(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}))
	mux.HandleFunc("PUT /api/v1/agent/evidence/{job}/chunks/{index}", bounded(func(w http.ResponseWriter, r *http.Request) {
		id, ok := job(r)
		index, err := strconv.ParseInt(r.PathValue("index"), 10, 64)
		if !ok || err != nil || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/octet-stream" {
			http.Error(w, "Invalid chunk request.", 400)
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = rc.SetWriteDeadline(time.Now().Add(5*time.Minute + 10*time.Second))
		r.Body = http.MaxBytesReader(w, r.Body, storage.EvidenceChunk+1)
		if e := s.EvidenceChunk(r.Context(), r.TLS, id, index, r.Header.Get("X-OpenRMM-SHA256"), r.Body); e != nil {
			fail(w, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	// The file a drop action writes, with Range support so an
	// interrupted download continues.
	mux.HandleFunc("GET /api/v1/agent/evidence/{job}/payload", func(w http.ResponseWriter, r *http.Request) {
		select {
		case payloadSlots <- struct{}{}:
			defer func() { <-payloadSlots }()
		default:
			w.Header().Set("Retry-After", "30")
			http.Error(w, "Downloads busy; retry shortly.", 429)
			return
		}
		id, ok := job(r)
		if !ok || r.URL.RawQuery != "" {
			http.Error(w, "Unknown job.", 404)
			return
		}
		f, _, e := s.DropPayload(r.Context(), r.TLS, id)
		if e != nil {
			fail(w, e)
			return
		}
		defer f.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Hour))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "", time.Time{}, f)
	})
	mux.HandleFunc("POST /api/v1/agent/evidence/{job}/finish", bounded(func(w http.ResponseWriter, r *http.Request) {
		id, ok := job(r)
		var in protocol.EvidenceFinish
		if !ok || !readJSON(w, r, &in) {
			if !ok {
				http.Error(w, "Unknown job.", 404)
			}
			return
		}
		if e := s.FinishEvidence(r.Context(), r.TLS, id, in); e != nil {
			fail(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}\n"))
	}))
}

func registerAgentUpdateDevice(mux *http.ServeMux, s *devices.Service) {
	respondError := func(w http.ResponseWriter, e error) {
		if errors.Is(e, storage.ErrAgentUpgrade) {
			http.Error(w, "Agent update unavailable or expired.", 409)
		} else {
			deviceAuthenticationError(w, e)
		}
	}
	mux.HandleFunc("POST /api/v1/agent/agent-upgrades/poll", func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var in struct{}
		if !readJSON(w, r, &in) {
			return
		}
		v, e := s.PollAgentUpgrade(r.Context(), r.TLS)
		if e != nil {
			respondError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("POST /api/v1/agent/agent-upgrades/result", func(w http.ResponseWriter, r *http.Request) {
		if _, e := s.Authenticate(r.Context(), r.TLS); e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var in protocol.AgentUpgradeResult
		if !readJSON(w, r, &in) {
			return
		}
		v, e := s.AgentUpgradeResult(r.Context(), r.TLS, in)
		if e != nil {
			respondError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
	mux.HandleFunc("GET /api/v1/agent/agent-upgrades/{job}/artifact", boundedFile(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" || !protocol.ValidID(r.PathValue("job")) {
			http.Error(w, "Invalid artifact request.", 400)
			return
		}
		release, f, e := s.AgentArtifact(r.Context(), r.TLS, r.PathValue("job"))
		if e != nil {
			respondError(w, e)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// ServeContent supports the agent's bounded streaming GET without loading the executable into memory.
		http.ServeContent(w, r, release.ID+".exe", time.Time{}, f)
	}))
}

func desktopError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, desktop.ErrInvalid), errors.Is(e, storage.ErrAuthentication):
		http.Error(w, "Desktop session is unavailable or has ended.", 404)
	case errors.Is(e, desktop.ErrUnavailable):
		http.Error(w, "Open the Windows desktop companion first. Only one session per device and four per server are allowed.", 409)
	default:
		http.Error(w, "Desktop support is temporarily unavailable.", 503)
	}
}

func registerDesktopDevice(mux *http.ServeMux, ds *devices.Service) {
	if ds == nil || ds.Desktop == nil {
		return
	}
	mux.HandleFunc("POST /api/v1/agent/desktop", func(w http.ResponseWriter, r *http.Request) {
		d, e := ds.Authenticate(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var p desktop.Exchange
		if !readJSONLimit(w, r, &p, desktop.MaxWire) {
			return
		}
		v, e := ds.Desktop.Exchange(r.Context(), d.ID, p)
		if e != nil {
			desktopError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
}

func terminalError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, terminal.ErrInvalid), errors.Is(e, storage.ErrAuthentication):
		http.Error(w, "Terminal session ended or unavailable.", 404)
	case errors.Is(e, terminal.ErrUnavailable):
		http.Error(w, "Terminal unavailable. Check that the terminal is turned on, the agent is connected and has no active terminal.", 409)
	default:
		http.Error(w, "Terminal temporarily unavailable.", 503)
	}
}

func registerTerminalDevice(mux *http.ServeMux, ds *devices.Service) {
	if ds == nil || ds.Terminal == nil {
		return
	}
	mux.HandleFunc("POST /api/v1/agent/terminal", func(w http.ResponseWriter, r *http.Request) {
		d, e := ds.Authenticate(r.Context(), r.TLS)
		if e != nil {
			deviceAuthenticationError(w, e)
			return
		}
		var p terminal.Exchange
		if !readJSONLimit(w, r, &p, terminal.MaxWire) {
			return
		}
		v, e := ds.Terminal.Exchange(r.Context(), d.ID, p)
		if e != nil {
			terminalError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	})
}
