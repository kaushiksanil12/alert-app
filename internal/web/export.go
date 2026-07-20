package web

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/store"
)

// ExportHandler streams findings as a CSV file (§3.14).
// GET /api/export.csv
// Optional query params: ?severity=HIGH&from=2024-01-01&to=2024-12-31
// No auth required — read-only (§4 Access control).
type ExportHandler struct {
	store *store.Store
}

// NewExportHandler creates a CSV export handler.
func NewExportHandler(st *store.Store) *ExportHandler {
	return &ExportHandler{store: st}
}

// ServeHTTP handles GET /api/export.csv.
func (h *ExportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := store.FindingFilter{
		ShowAcknowledged: true,
		Severity:         r.URL.Query().Get("severity"),
	}

	if fromStr := r.URL.Query().Get("from"); fromStr != "" {
		t, err := time.Parse("2006-01-02", fromStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid 'from' date: %s (use YYYY-MM-DD)", fromStr), http.StatusBadRequest)
			return
		}
		filter.From = t
	}
	if toStr := r.URL.Query().Get("to"); toStr != "" {
		t, err := time.Parse("2006-01-02", toStr)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid 'to' date: %s (use YYYY-MM-DD)", toStr), http.StatusBadRequest)
			return
		}
		filter.To = t.Add(24 * time.Hour) // inclusive
	}

	findings, err := h.store.GetFindings(filter)
	if err != nil {
		slog.Error("export: failed to get findings", "err", err)
		http.Error(w, "internal error fetching findings", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("vuln-findings-%s.csv", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	cw := csv.NewWriter(w)
	// Header row (§3.14 required columns)
	header := []string{"technology", "cve_id", "severity", "published", "fixed_version", "acknowledged", "source", "url"}
	if err := cw.Write(header); err != nil {
		slog.Error("export: write header", "err", err)
		return
	}

	for _, sf := range findings {
		published := ""
		if !sf.Published.IsZero() {
			published = sf.Published.Format("2006-01-02")
		}
		ackStr := "false"
		if sf.Acknowledged {
			ackStr = "true"
		}
		row := []string{
			sf.Technology,
			sf.CVEID,
			string(sf.Severity),
			published,
			sf.FixedVersion,
			ackStr,
			sf.Source,
			sf.URL,
		}
		if err := cw.Write(row); err != nil {
			slog.Error("export: write row", "cve", sf.CVEID, "err", err)
			return
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		slog.Error("export: flush error", "err", err)
	}

	slog.Info("csv export complete", "rows", len(findings))
}
