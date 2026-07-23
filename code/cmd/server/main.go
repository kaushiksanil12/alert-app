// Package main is the entrypoint for the vulnerability alert service.
// It embeds the tzdata database (required for distroless/static images which
// ship no OS timezone data), wires all components together, and starts the
// HTTP server and daily scheduler.
package main

import (
	_ "time/tzdata" // embed IANA timezone database — required for distroless (§3.1)

	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/alert"
	"github.com/kaushik/vuln-alert-service/internal/auth"
	"github.com/kaushik/vuln-alert-service/internal/config"
	"github.com/kaushik/vuln-alert-service/internal/fetchers"
	"github.com/kaushik/vuln-alert-service/internal/scheduler"
	"github.com/kaushik/vuln-alert-service/internal/store"
	"github.com/kaushik/vuln-alert-service/internal/web"
)

func main() {
	// Structured JSON logging — parseable by any log aggregator.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	slog.Info("vuln-alert-service starting")

	// ── Load config ───────────────────────────────────────────────────────────
	sourcesPath := envOr("SOURCES_PATH", "config/sources.yaml")
	cfg, err := config.Load(sourcesPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Log config (never log secrets).
	slog.Info("config loaded",
		"timezone", cfg.TZ,
		"data_dir", cfg.DataDir,
		"port", cfg.Port,
		"sources", len(cfg.Sources),
		"min_alert_severity", cfg.MinAlertSeverity,
		"retention_days", cfg.RetentionDays,
		"weekly_digest_day", cfg.WeeklyDigestDay,
		"failure_threshold", cfg.FailureAlertThreshold,
		"secrets", cfg.RedactedSecrets(),
	)

	// ── Open store ────────────────────────────────────────────────────────────
	dbPath := filepath.Join(cfg.DataDir, "vuln.db")
	st, err := store.Open(dbPath)
	if err != nil {
		slog.Error("failed to open store", "path", dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()
	slog.Info("store opened", "path", dbPath)

	users, err := store.NewUserStore(st.DB())
	if err != nil {
		slog.Error("failed to create users store", "err", err)
		os.Exit(1)
	}

	tasks, err := store.NewTaskStore(st.DB())
	if err != nil {
		slog.Error("failed to create tasks store", "err", err)
		os.Exit(1)
	}

	sessions, err := auth.NewSessionStore(st.DB(), 24*time.Hour)
	if err != nil {
		slog.Error("failed to create session store", "err", err)
		os.Exit(1)
	}

	// Bootstrap Admin
	if err := users.Bootstrap(cfg.BootstrapAdminEmail); err != nil {
		slog.Error("failed to bootstrap admin", "err", err)
	}

	// ── Build fetchers from sources.yaml ──────────────────────────────────────
	fetcherList := buildFetchers(cfg)
	slog.Info("fetchers registered", "count", len(fetcherList))

	// ── Build alert clients ───────────────────────────────────────────────────
	mainClient := alert.NewTeamsClient(cfg.TeamsWebhookURL)

	var critClient *alert.TeamsClient
	if cfg.CriticalWebhookURL != "" {
		critClient = alert.NewTeamsClient(cfg.CriticalWebhookURL)
	}

	digestWebhook := cfg.WeeklyDigestWebhookURL
	if digestWebhook == "" {
		digestWebhook = cfg.TeamsWebhookURL
	}
	digestClient := alert.NewTeamsClient(digestWebhook)

	filter := alert.NewSeverityFilter(cfg.MinAlertSeverity)
	overdueAlerter := alert.NewOverdueAlerter(cfg.TeamsWebhookURL)

	// ── Build scheduler ───────────────────────────────────────────────────────
	sched := scheduler.New(cfg, st, tasks, fetcherList, mainClient, critClient, digestClient, overdueAlerter, filter)

	// ── Build web handlers ────────────────────────────────────────────────────
	sourceNames := make([]string, 0, len(cfg.Sources))
	for _, s := range cfg.Sources {
		sourceNames = append(sourceNames, s.Name)
	}

	dashHandler, err := web.NewDashboardHandler(st, tasks, users, sched, sourceNames)
	if err != nil {
		slog.Error("failed to create dashboard handler", "err", err)
		os.Exit(1)
	}

	tasksHandler, err := web.NewTasksHandler(tasks, users)
	if err != nil {
		slog.Error("failed to create tasks handler", "err", err)
		os.Exit(1)
	}

	usersHandler, err := web.NewUsersHandler(users)
	if err != nil {
		slog.Error("failed to create users handler", "err", err)
		os.Exit(1)
	}

	var oidcClient *auth.OIDCClient
	if cfg.EntraClientID != "" {
		oidcClient, err = auth.NewOIDCClient(
			context.Background(),
			cfg.EntraTenantID,
			cfg.EntraClientID,
			cfg.EntraClientSecret,
			cfg.BaseURL+"/auth/callback",
		)
		if err != nil {
			slog.Error("failed to create OIDC client", "err", err)
			os.Exit(1)
		}
	}

	loginHandler, err := web.NewLoginHandler(oidcClient, sessions, users)
	if err != nil {
		slog.Error("failed to create login handler", "err", err)
		os.Exit(1)
	}

	// ── Register routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()
	
	// Unauthenticated routes
	if oidcClient != nil {
		mux.HandleFunc("/login", loginHandler.ServeHTTP)
		mux.HandleFunc("/auth/initiate", loginHandler.InitiateHandler)
		mux.HandleFunc("/auth/callback", loginHandler.CallbackHandler)
		mux.HandleFunc("/logout", loginHandler.LogoutHandler)
	}
	mux.Handle("/healthz", web.NewHealthzHandler(st))
	mux.Handle("/api/export.csv", web.NewExportHandler(st)) // Read-only

	// Authenticated routes
	authMux := http.NewServeMux()
	authMux.Handle("/", dashHandler)
	authMux.HandleFunc("/api/run-now", dashHandler.RunNowHandler)

	// Tasks API
	authMux.HandleFunc("/tasks", tasksHandler.MyTasksHandler)
	authMux.Handle("/api/tasks", auth.RequireRole(auth.RoleAdmin, auth.RoleManager)(http.HandlerFunc(tasksHandler.CreateTaskHandler)))
	authMux.Handle("/api/tasks/bulk", auth.RequireRole(auth.RoleAdmin, auth.RoleManager)(http.HandlerFunc(tasksHandler.BulkCreateHandler)))
	authMux.HandleFunc("/api/tasks/{id}/status", tasksHandler.UpdateStatusHandler)
	authMux.Handle("/api/tasks/{id}/reassign", auth.RequireRole(auth.RoleAdmin, auth.RoleManager)(http.HandlerFunc(tasksHandler.ReassignHandler)))
	authMux.HandleFunc("/api/tasks/{id}/note", tasksHandler.AddNoteHandler)

	// Admin Users API
	authMux.Handle("/admin/users", auth.RequireRole(auth.RoleAdmin)(usersHandler))

	// Wrap auth routes with middleware
	var handler http.Handler = authMux
	if oidcClient != nil {
		handler = auth.RequireSession(sessions, users, authMux)
	}
	handler = auth.CSRFMiddleware(handler)
	
	// Mount auth routes onto main mux
	mux.Handle("/", handler)

	// Add Developer Signature Header
	signedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Developed-By", "Kaushik")
		mux.ServeHTTP(w, r)
	})

	// ── Start HTTP server ─────────────────────────────────────────────────────
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      signedMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		slog.Info("HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "err", err)
			os.Exit(1)
		}
	}()

	// ── Start scheduler ───────────────────────────────────────────────────────
	go sched.Run(ctx)

	slog.Info("service ready")

	// ── Wait for shutdown ─────────────────────────────────────────────────────
	<-ctx.Done()
	slog.Info("shutdown signal received — draining...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "err", err)
	}
	slog.Info("shutdown complete")
}

// buildFetchers constructs all Fetcher instances from the sources config.
// Each fetcher is wrapped with retry (3 attempts, 5s base delay).
func buildFetchers(cfg *config.AppConfig) []fetchers.Fetcher {
	var list []fetchers.Fetcher
	const maxAttempts = 3
	const baseDelay = 5 * time.Second

	for _, src := range cfg.Sources {
		var f fetchers.Fetcher
		switch src.Type {
		case "osv":
			f = fetchers.NewOSVFetcher(src.Name, src.Technology, src.Ecosystem, src.Package)
		case "nvd":
			f = fetchers.NewNVDFetcher(src.Name, src.Technology, src.Keyword, src.MinSeverity, cfg.NVDAPIKey)
		case "nodejs_rss":
			f = fetchers.NewNodeJSRSSFetcher(src.Name, src.Technology, src.URL)
		case "vendor_rss":
			f = fetchers.NewVendorRSSFetcher(src.Name, src.Technology, src.URL, src.Format)
		case "osv_gomod":
			f = fetchers.NewOSVGoModFetcher(src.Name, src.Path)
		default:
			slog.Warn("unknown source type — skipping", "name", src.Name, "type", src.Type)
			continue
		}
		list = append(list, fetchers.WithRetry(f, maxAttempts, baseDelay))
	}
	return list
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
