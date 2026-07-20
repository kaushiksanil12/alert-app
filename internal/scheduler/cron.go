package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/alert"
	"github.com/kaushik/vuln-alert-service/internal/config"
	"github.com/kaushik/vuln-alert-service/internal/fetchers"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

// Scheduler runs the nightly vulnerability fetch job at local midnight,
// handles manual triggers, and sends the weekly digest.
type Scheduler struct {
	cfg            *config.AppConfig
	store          *store.Store
	fetcherList    []fetchers.Fetcher
	mainClient     *alert.TeamsClient
	critClient     *alert.TeamsClient // nil if CRITICAL_WEBHOOK_URL not set
	digestClient   *alert.TeamsClient
	filter         *alert.SeverityFilter
	manualTrigger  chan struct{}
	mu             sync.Mutex // protects isRunning
	isRunning      bool
}

// New creates a Scheduler. All external dependencies are injected.
func New(
	cfg *config.AppConfig,
	st *store.Store,
	fl []fetchers.Fetcher,
	mainClient *alert.TeamsClient,
	critClient *alert.TeamsClient,
	digestClient *alert.TeamsClient,
	filter *alert.SeverityFilter,
) *Scheduler {
	return &Scheduler{
		cfg:           cfg,
		store:         st,
		fetcherList:   fl,
		mainClient:    mainClient,
		critClient:    critClient,
		digestClient:  digestClient,
		filter:        filter,
		manualTrigger: make(chan struct{}, 1),
	}
}

// TriggerNow enqueues a manual run. Non-blocking — drops if already queued.
func (s *Scheduler) TriggerNow() {
	select {
	case s.manualTrigger <- struct{}{}:
		slog.Info("manual run trigger queued")
	default:
		slog.Info("manual run trigger dropped — already queued or run in progress")
	}
}

// Run starts the scheduler loop. Blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("scheduler starting",
		"timezone", s.cfg.TZ,
		"min_alert_severity", s.cfg.MinAlertSeverity,
		"failure_threshold", s.cfg.FailureAlertThreshold,
	)

	for {
		nextRun := nextMidnight(s.cfg.Location)
		slog.Info("next scheduled run", "at", nextRun.Format(time.RFC3339))

		select {
		case <-ctx.Done():
			slog.Info("scheduler shutting down")
			return

		case <-s.manualTrigger:
			slog.Info("manual run triggered")
			s.runOnce(ctx)

		case <-time.After(time.Until(nextRun)):
			slog.Info("scheduled midnight run starting", "local_time", time.Now().In(s.cfg.Location).Format(time.RFC3339))
			s.runOnce(ctx)

			// Check if today is the weekly digest day.
			today := time.Now().In(s.cfg.Location).Weekday().String()
			if today == s.cfg.WeeklyDigestDay {
				s.runWeeklyDigest(ctx)
			}
		}
	}
}

// runOnce executes one full fetch+dedup+alert cycle.
func (s *Scheduler) runOnce(ctx context.Context) {
	s.mu.Lock()
	if s.isRunning {
		slog.Warn("run already in progress — skipping")
		s.mu.Unlock()
		return
	}
	s.isRunning = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.isRunning = false
		s.mu.Unlock()
	}()

	runCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()

	slog.Info("run started", "sources", len(s.fetcherList))
	runStart := time.Now()
	var allNewFindings []fetchers.Finding

	for _, f := range s.fetcherList {
		newFindings := s.runFetcher(runCtx, f)
		allNewFindings = append(allNewFindings, newFindings...)
	}

	// Alert on new findings.
	if len(allNewFindings) > 0 {
		toAlert, toEscalate := s.filter.FilterFindings(allNewFindings)

		// Main channel — batched, severity-filtered.
		if len(toAlert) > 0 {
			if err := s.mainClient.SendFindings(runCtx, toAlert); err != nil {
				slog.Error("failed to send main Teams alert", "err", err)
			}
		}

		// Escalation channel — HIGH/CRITICAL only, independent of main batch.
		if len(toEscalate) > 0 && s.critClient != nil && s.critClient.IsConfigured() {
			if err := s.critClient.SendFindings(runCtx, toEscalate); err != nil {
				slog.Error("failed to send critical Teams alert", "err", err)
			}
		}
	}

	// Prune old finding records.
	if pruned, err := s.store.Prune(s.cfg.RetentionDays); err != nil {
		slog.Error("retention prune failed", "err", err)
	} else if pruned > 0 {
		slog.Info("pruned old findings", "count", pruned)
	}

	if err := s.store.SetLastRunTime(runStart); err != nil {
		slog.Error("failed to set last run time", "err", err)
	}

	slog.Info("run complete",
		"duration", time.Since(runStart).Round(time.Second),
		"new_findings", len(allNewFindings),
	)
}

// runFetcher runs one fetcher, handles baseline logic, deduplication,
// consecutive-failure tracking, and meta-alerts.
func (s *Scheduler) runFetcher(ctx context.Context, f fetchers.Fetcher) []fetchers.Finding {
	source := f.Name()

	rawFindings, err := f.Fetch(ctx)
	if err != nil {
		slog.Error("fetcher failed", "source", source, "err", err)
		if stErr := s.store.RecordSourceStatus(source, false, err.Error(), 0); stErr != nil {
			slog.Error("failed to record source status", "source", source, "err", stErr)
		}

		// Check if we need to send a meta-alert.
		status, _ := s.store.GetSourceStatus(source)
		if status.ConsecutiveFailures >= s.cfg.FailureAlertThreshold {
			slog.Warn("source failure threshold exceeded — sending meta-alert",
				"source", source,
				"consecutive_failures", status.ConsecutiveFailures,
			)
			metaCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if mErr := s.mainClient.SendMetaAlert(metaCtx, source, status.ConsecutiveFailures); mErr != nil {
				slog.Error("failed to send meta-alert", "source", source, "err", mErr)
			}
		}
		return nil
	}

	// Global safeguard: limit to 20 vulnerabilities per run per source
	if len(rawFindings) > 20 {
		rawFindings = rawFindings[:20]
	}

	slog.Info("fetcher succeeded", "source", source, "raw_findings", len(rawFindings))

	// First-run baseline check (§3.2).
	baselineDone, err := s.store.IsBaselineDone(source)
	if err != nil {
		slog.Error("failed to check baseline", "source", source, "err", err)
		return nil
	}
	if !baselineDone {
		// First run — record all current findings as baseline, alert on nothing.
		if err := s.store.MarkBaseline(source, rawFindings); err != nil {
			slog.Error("failed to mark baseline", "source", source, "err", err)
		}
		if err := s.store.RecordSourceStatus(source, true, "", 0); err != nil {
			slog.Error("failed to record source status", "source", source, "err", err)
		}
		return nil
	}

	// Deduplication — only process genuinely new findings.
	var newFindings []fetchers.Finding
	for _, finding := range rawFindings {
		if finding.CVEID == "" {
			continue
		}
		isNew, err := s.store.IsNew(source, finding.CVEID)
		if err != nil {
			slog.Error("dedup check failed", "source", source, "cve", finding.CVEID, "err", err)
			continue
		}
		if !isNew {
			slog.Debug("dedup: already seen", "source", source, "cve", finding.CVEID)
			continue
		}

		// Record finding — both dedup and full record.
		sf := fetchers.StoredFinding{
			Finding:   finding,
			FirstSeen: time.Now(),
		}
		if err := s.store.RecordFinding(sf); err != nil {
			slog.Error("failed to record finding", "source", source, "cve", finding.CVEID, "err", err)
			continue
		}

		slog.Info("new finding", "source", source, "cve", finding.CVEID, "severity", finding.Severity)
		newFindings = append(newFindings, finding)
	}

	if err := s.store.RecordSourceStatus(source, true, "", len(newFindings)); err != nil {
		slog.Error("failed to record source status", "source", source, "err", err)
	}

	return newFindings
}

// runWeeklyDigest fetches findings from the past 7 days and sends the digest.
func (s *Scheduler) runWeeklyDigest(ctx context.Context) {
	slog.Info("weekly digest run starting")
	since := time.Now().AddDate(0, 0, -7)

	findings, err := s.store.GetFindingsSince(since)
	if err != nil {
		slog.Error("failed to fetch findings for weekly digest", "err", err)
		return
	}

	digestCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	sender := alert.NewDigestSender(s.digestClient)
	if err := sender.Send(digestCtx, findings, since); err != nil {
		slog.Error("weekly digest send failed", "err", err)
	}
}

// nextMidnight returns the next local midnight in the given location.
func nextMidnight(loc *time.Location) time.Time {
	now := time.Now().In(loc)
	tomorrow := now.AddDate(0, 0, 1)
	return time.Date(
		tomorrow.Year(), tomorrow.Month(), tomorrow.Day(),
		0, 0, 0, 0,
		loc,
	)
}
