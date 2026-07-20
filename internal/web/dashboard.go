package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
	"github.com/kaushik/vuln-alert-service/internal/scheduler"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

//go:embed templates/*
var templateFS embed.FS

// DashboardHandler serves the main dashboard and write API endpoints.
type DashboardHandler struct {
	store     *store.Store
	sched     *scheduler.Scheduler
	runToken  string // RUN_NOW_TOKEN — bearer token for write endpoints
	tmpl      *template.Template
	sourceNames []string
}

// NewDashboardHandler creates the dashboard handler.
func NewDashboardHandler(st *store.Store, sched *scheduler.Scheduler, runToken string, sourceNames []string) (*DashboardHandler, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"severityClass":  severityClass,
		"formatTime":     formatTime,
		"formatDateOnly": formatDateOnly,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &DashboardHandler{
		store:       st,
		sched:       sched,
		runToken:    runToken,
		tmpl:        tmpl,
		sourceNames: sourceNames,
	}, nil
}

// dashboardData is the template data model.
type dashboardData struct {
	LastRun         string
	Sources         []sourceRow
	Findings        []fetchers.StoredFinding
	ShowAcknowledged bool
	SeverityFilter  string
	TotalFindings   int
	NewToday        int
}

type sourceRow struct {
	Name                string
	OK                  bool
	Error               string
	LastAttempt         string
	ConsecutiveFailures int
	FindingsThisRun     int
}

// ServeHTTP handles GET / (dashboard page).
func (h *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	showAck := r.URL.Query().Get("show_acknowledged") == "1"
	severityFilter := r.URL.Query().Get("severity")

	filter := store.FindingFilter{
		ShowAcknowledged: showAck,
		Severity:         severityFilter,
	}
	findings, err := h.store.GetFindings(filter)
	if err != nil {
		slog.Error("dashboard: get findings", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	lastRun, _ := h.store.GetLastRunTime()
	lastRunStr := "Never"
	if !lastRun.IsZero() {
		lastRunStr = lastRun.Format("2006-01-02 15:04:05 MST")
	}

	statuses, err := h.store.GetAllSourceStatuses()
	if err != nil {
		slog.Error("dashboard: get statuses", "err", err)
	}

	sources := make([]sourceRow, 0, len(h.sourceNames))
	for _, name := range h.sourceNames {
		row := sourceRow{Name: name, OK: true}
		if st, ok := statuses[name]; ok {
			row.OK = st.OK
			row.Error = st.Error
			row.ConsecutiveFailures = st.ConsecutiveFailures
			row.FindingsThisRun = st.FindingsThisRun
			if !st.LastAttempt.IsZero() {
				row.LastAttempt = st.LastAttempt.Format("2006-01-02 15:04")
			}
		}
		sources = append(sources, row)
	}

	// Count new findings in the last 24 hours.
	newToday := 0
	since24h := time.Now().Add(-24 * time.Hour)
	for _, f := range findings {
		if f.FirstSeen.After(since24h) {
			newToday++
		}
	}

	data := dashboardData{
		LastRun:          lastRunStr,
		Sources:          sources,
		Findings:         findings,
		ShowAcknowledged: showAck,
		SeverityFilter:   severityFilter,
		TotalFindings:    len(findings),
		NewToday:         newToday,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("dashboard: render template", "err", err)
	}
}

// RunNowHandler handles POST /api/run-now (bearer-auth required).
func (h *DashboardHandler) RunNowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.checkBearer(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.sched.TriggerNow()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","message":"run triggered"}`))
	slog.Info("manual run triggered via API")
}

// AcknowledgeHandler handles POST /api/acknowledge/{source}/{cve_id} (bearer-auth required).
func (h *DashboardHandler) AcknowledgeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.checkBearer(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract source and cve_id from path: /api/acknowledge/{source}/{cve_id}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/acknowledge/"), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path — expected /api/acknowledge/{source}/{cve_id}", http.StatusBadRequest)
		return
	}
	source, cveID := parts[0], parts[1]

	if err := h.store.Acknowledge(source, cveID); err != nil {
		slog.Error("acknowledge failed", "source", source, "cve", cveID, "err", err)
		http.Error(w, "not found or internal error", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"acknowledged"}`))
	slog.Info("finding acknowledged", "source", source, "cve", cveID)
}

// UnacknowledgeHandler handles POST /api/unacknowledge/{source}/{cve_id} (bearer-auth required).
func (h *DashboardHandler) UnacknowledgeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.checkBearer(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/unacknowledge/"), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "invalid path — expected /api/unacknowledge/{source}/{cve_id}", http.StatusBadRequest)
		return
	}
	source, cveID := parts[0], parts[1]

	if err := h.store.Unacknowledge(source, cveID); err != nil {
		slog.Error("unacknowledge failed", "source", source, "cve", cveID, "err", err)
		http.Error(w, "not found or internal error", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"unacknowledged"}`))
}

// checkBearer validates the Authorization: Bearer <token> header.
func (h *DashboardHandler) checkBearer(r *http.Request) bool {
	if h.runToken == "" {
		// No token configured — reject all (safer than permitting all).
		slog.Warn("RUN_NOW_TOKEN not set — rejecting write request")
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	return strings.TrimPrefix(auth, "Bearer ") == h.runToken
}

// ─── Template helpers ─────────────────────────────────────────────────────────

func severityClass(s fetchers.Severity) string {
	switch s {
	case fetchers.SeverityCritical:
		return "sev-critical"
	case fetchers.SeverityHigh:
		return "sev-high"
	case fetchers.SeverityMedium:
		return "sev-medium"
	case fetchers.SeverityLow:
		return "sev-low"
	default:
		return "sev-unknown"
	}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

func formatDateOnly(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02")
}
