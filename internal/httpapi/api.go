// Package httpapi exposes a small, authenticated-by-configuration HTTP surface.
package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/model"
)

const maxRequestBytes = 32 << 10

type API struct {
	Engine      *engine.Engine
	Token       string // backward-compatible single-token development mode
	IngestToken string // collector-only credential; never grants incident read access
	AdminToken  string // analyst/read-response credential; never grants event writes
}

func (api *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !api.Engine.Ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		s := api.Engine.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# TYPE crg_events_stored gauge\ncrg_events_stored %d\n", s.Events)
		fmt.Fprintf(w, "# TYPE crg_incidents gauge\ncrg_incidents %d\n", s.Incidents)
		fmt.Fprintf(w, "# TYPE crg_dry_run_responses gauge\ncrg_dry_run_responses %d\n", s.DryRunResponses)
		fmt.Fprintf(w, "# TYPE crg_event_capacity gauge\ncrg_event_capacity %d\n", s.Capacity)
		ready := 0
		if api.Engine.Ready() {
			ready = 1
		}
		fmt.Fprintf(w, "# TYPE crg_ready gauge\ncrg_ready %d\n", ready)
	})
	mux.HandleFunc("POST /v1/events", api.events)
	mux.HandleFunc("GET /v1/incidents", api.list)
	mux.HandleFunc("GET /v1/incidents/{id}", api.get)
	mux.HandleFunc("POST /v1/incidents/{id}/response", api.response)
	mux.HandleFunc("GET /v1/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, api.Engine.Stats()) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			wanted := api.AdminToken
			if r.URL.Path == "/v1/events" {
				wanted = api.IngestToken
			}
			if wanted == "" {
				wanted = api.Token
			}
			if api.IngestToken != "" || api.AdminToken != "" || api.Token != "" {
				if wanted == "" {
					w.Header().Set("WWW-Authenticate", "Bearer")
					problem(w, 401, "credential not configured for this role")
					return
				}
				supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				suppliedHash, wantedHash := sha256.Sum256([]byte(supplied)), sha256.Sum256([]byte(wanted))
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(suppliedHash[:], wantedHash[:]) != 1 {
					w.Header().Set("WWW-Authenticate", "Bearer")
					problem(w, 401, "unauthorized")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"error": detail})
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	defer r.Body.Close()
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra json.RawMessage
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("only one JSON object is allowed")
		}
		return fmt.Errorf("invalid JSON after object: %w", err)
	}
	return nil
}

func (api *API) events(w http.ResponseWriter, r *http.Request) {
	var e model.Event
	if err := decode(w, r, &e); err != nil {
		problem(w, decodeStatus(err), err.Error())
		return
	}
	created, err := api.Engine.Ingest(e)
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrConflict):
			problem(w, 409, err.Error())
		case errors.Is(err, engine.ErrFull):
			problem(w, 507, err.Error())
		default:
			if validation := e.Validate(); validation != nil {
				problem(w, 400, validation.Error())
			} else {
				problem(w, 500, "event storage failed")
			}
		}
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"id": e.ID, "created": created})
}

func pageParam(r *http.Request, key string, def, max int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 || v > max {
		return 0, fmt.Errorf("%s must be between 0 and %d", key, max)
	}
	return v, nil
}
func (api *API) list(w http.ResponseWriter, r *http.Request) {
	limit, err := pageParam(r, "limit", 100, 500)
	if err != nil || limit == 0 {
		problem(w, 400, "limit must be between 1 and 500")
		return
	}
	offset, err := pageParam(r, "offset", 0, 100000000)
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	items, total := api.Engine.List(limit, offset)
	writeJSON(w, 200, map[string]any{"incidents": items, "total": total, "limit": limit, "offset": offset})
}
func (api *API) get(w http.ResponseWriter, r *http.Request) {
	incident, ok := api.Engine.Get(r.PathValue("id"))
	if !ok {
		problem(w, 404, "incident not found")
		return
	}
	writeJSON(w, 200, incident)
}
func (api *API) response(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RequestID string `json:"request_id"`
		Action    string `json:"action"`
		Reason    string `json:"reason"`
	}
	if err := decode(w, r, &request); err != nil {
		problem(w, decodeStatus(err), err.Error())
		return
	}
	action := model.ResponseAction{RequestID: request.RequestID, IncidentID: r.PathValue("id"), Action: request.Action, Reason: request.Reason}
	if err := action.Validate(); err != nil {
		problem(w, 400, err.Error())
		return
	}
	result, created, err := api.Engine.DryRunResponse(action)
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrNotFound):
			problem(w, 404, err.Error())
		case errors.Is(err, engine.ErrConflict):
			problem(w, 409, err.Error())
		case errors.Is(err, engine.ErrFull):
			problem(w, 507, err.Error())
		default:
			problem(w, 500, "response audit storage failed")
		}
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, result)
}

func decodeStatus(err error) int {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}
