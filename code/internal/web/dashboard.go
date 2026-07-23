package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/auth"
	"github.com/kaushik/vuln-alert-service/internal/fetchers"
	"github.com/kaushik/vuln-alert-service/internal/scheduler"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

//go:embed templates/*
var templateFS embed.FS

// DashboardHandler serves the main dashboard and write API endpoints.
type DashboardHandler struct {
	store       *store.Store
	tasks       *store.TaskStore
	users       *store.UserStore
	sched       *scheduler.Scheduler
	tmpl        *template.Template
	sourceNames []string
}

// NewDashboardHandler creates the dashboard handler.
func NewDashboardHandler(st *store.Store, tasks *store.TaskStore, users *store.UserStore, sched *scheduler.Scheduler, sourceNames []string) (*DashboardHandler, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"severityClass":  severityClass,
		"formatTime":     formatTime,
		"formatDateOnly": formatDateOnly,
		"lower":          strings.ToLower,
		"hasTasks": func(t []store.Task) bool { return len(t) > 0 },
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &DashboardHandler{
		store:       st,
		tasks:       tasks,
		users:       users,
		sched:       sched,
		tmpl:        tmpl,
		sourceNames: sourceNames,
	}, nil
}

// dashboardData is the template data model.
type dashboardData struct {
	LastRun         string
	Sources         []sourceRow
	Findings        []findingRow
	Users           []store.User
	Session         *auth.SessionData
	CSRFToken       string
	SeverityFilter  string
	SourceFilter    string
	ThisWeek        int
	PreviousWeek    int
	OlderFindings   int
}

type findingRow struct {
	fetchers.StoredFinding
	Tasks []store.Task
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

	sess := auth.SessionFromContext(r)
	severityFilter := r.URL.Query().Get("severity")
	sourceFilter := r.URL.Query().Get("source")

	filter := store.FindingFilter{
		Severity: severityFilter,
		Source:   sourceFilter,
	}
	rawFindings, err := h.store.GetFindings(filter)
	if err != nil {
		slog.Error("dashboard: get findings", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	allTasks, err := h.tasks.ListTasks(store.TaskFilter{})
	if err != nil {
		slog.Error("dashboard: get tasks", "err", err)
	}
	taskMap := make(map[string][]store.Task)
	for _, t := range allTasks {
		taskMap[t.FindingKey] = append(taskMap[t.FindingKey], t)
	}

	var findings []findingRow
	for _, f := range rawFindings {
		findings = append(findings, findingRow{
			StoredFinding: f,
			Tasks:         taskMap[f.DeduplicateKey()],
		})
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

	now := time.Now()
	thisWeekBoundary := now.AddDate(0, 0, -7)
	prevWeekBoundary := now.AddDate(0, 0, -14)

	var thisWeek, prevWeek, older int
	for _, f := range rawFindings {
		if f.FirstSeen.After(thisWeekBoundary) {
			thisWeek++
		} else if f.FirstSeen.After(prevWeekBoundary) {
			prevWeek++
		} else {
			older++
		}
	}

	var users []store.User
	if sess != nil && (sess.Role == auth.RoleAdmin || sess.Role == auth.RoleManager) {
		allUsers, _ := h.users.ListUsers()
		for _, u := range allUsers {
			if string(u.Role) == auth.RoleViewer {
				continue
			}
			if sess.Role == auth.RoleManager && string(u.Role) == auth.RoleAdmin {
				continue
			}
			users = append(users, u)
		}
	}

	data := dashboardData{
		LastRun:        lastRunStr,
		Sources:        sources,
		Findings:       findings,
		Session:        sess,
		CSRFToken:      auth.CSRFToken(r),
		SeverityFilter: severityFilter,
		SourceFilter:   sourceFilter,
		ThisWeek:       thisWeek,
		PreviousWeek:   prevWeek,
		OlderFindings:  older,
		Users:          users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("dashboard: render template", "err", err)
	}
}

// RunNowHandler handles POST /api/run-now (bearer-auth or session required).
func (h *DashboardHandler) RunNowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	sess := auth.SessionFromContext(r)
	if sess == nil {
		// Just fail if no session is present.
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	} else if sess.Role != auth.RoleAdmin && sess.Role != auth.RoleManager {
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	h.sched.TriggerNow()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","message":"run triggered"}`))
	slog.Info("manual run triggered via API")
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
