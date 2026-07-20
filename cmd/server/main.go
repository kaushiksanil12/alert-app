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

	// ── Build scheduler ───────────────────────────────────────────────────────
	sched := scheduler.New(cfg, st, fetcherList, mainClient, critClient, digestClient, filter)

	// ── Build web handlers ────────────────────────────────────────────────────
	sourceNames := make([]string, 0, len(cfg.Sources))
	for _, s := range cfg.Sources {
		sourceNames = append(sourceNames, s.Name)
	}

	dashHandler, err := web.NewDashboardHandler(st, sched, sourceNames)
	if err != nil {
		slog.Error("failed to create dashboard handler", "err", err)
		os.Exit(1)
	}

	// ── Register routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/", dashHandler)
	mux.HandleFunc("/api/run-now", dashHandler.RunNowHandler)
	mux.HandleFunc("/api/acknowledge/", dashHandler.AcknowledgeHandler)
	mux.HandleFunc("/api/unacknowledge/", dashHandler.UnacknowledgeHandler)
	mux.Handle("/api/export.csv", web.NewExportHandler(st))
	mux.Handle("/healthz", web.NewHealthzHandler(st))

	// ── Start HTTP server ─────────────────────────────────────────────────────
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      mux,
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
