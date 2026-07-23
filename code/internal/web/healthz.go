package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/store"
)

// HealthzHandler returns process health and last-run timestamp (§3.8).
type HealthzHandler struct {
	store   *store.Store
	started time.Time
}

// NewHealthzHandler creates a healthz handler.
func NewHealthzHandler(st *store.Store) *HealthzHandler {
	return &HealthzHandler{store: st, started: time.Now()}
}

type healthzResponse struct {
	Status      string `json:"status"`
	LastRun     string `json:"last_run"`
	Uptime      string `json:"uptime"`
	StartedAt   string `json:"started_at"`
}

// ServeHTTP handles GET /healthz.
func (h *HealthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	lastRun, err := h.store.GetLastRunTime()
	lastRunStr := "never"
	if err == nil && !lastRun.IsZero() {
		lastRunStr = lastRun.Format(time.RFC3339)
	} else if err != nil {
		slog.Warn("healthz: failed to read last run time", "err", err)
	}

	resp := healthzResponse{
		Status:    "ok",
		LastRun:   lastRunStr,
		Uptime:    time.Since(h.started).Round(time.Second).String(),
		StartedAt: h.started.Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("healthz encode error", "err", err)
	}
}
