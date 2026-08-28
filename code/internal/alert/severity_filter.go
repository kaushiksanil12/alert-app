package alert

import (
	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

// SeverityFilter determines which findings should be alerted on.
// Every finding is still stored and dedup'd regardless of this threshold —
// it gates the alert only, never the record (§3.10).
type SeverityFilter struct {
	minSeverity fetchers.Severity
}

// NewSeverityFilter creates a filter with the given minimum severity label.
// Label must be one of: LOW, MEDIUM, HIGH, CRITICAL (case-insensitive).
// Defaults to LOW (alert on everything) if the label is unrecognised.
func NewSeverityFilter(minLabel string) *SeverityFilter {
	sev := fetchers.SeverityLow
	switch minLabel {
	case "LOW", "low":
		sev = fetchers.SeverityLow
	case "MEDIUM", "medium":
		sev = fetchers.SeverityMedium
	case "HIGH", "high":
		sev = fetchers.SeverityHigh
	case "CRITICAL", "critical":
		sev = fetchers.SeverityCritical
	}
	return &SeverityFilter{minSeverity: sev}
}

// ShouldAlert reports whether the finding meets the minimum severity threshold
// for the main daily alert channel.
func (sf *SeverityFilter) ShouldAlert(f fetchers.Finding) bool {
	return f.Severity.AtLeast(sf.minSeverity)
}

// ShouldEscalate reports whether the finding should be sent to the dedicated
// HIGH/CRITICAL escalation webhook (CRITICAL_WEBHOOK_URL), independent of the
// daily batch and independent of MIN_ALERT_SEVERITY (§3.10).
func (sf *SeverityFilter) ShouldEscalate(f fetchers.Finding) bool {
	return f.Severity == fetchers.SeverityHigh || f.Severity == fetchers.SeverityCritical
}

// FilterFindings splits a batch of findings into:
//   - toAlert: meets MIN_ALERT_SEVERITY, goes to main channel
//   - toEscalate: HIGH or CRITICAL, goes to escalation channel
//
// Both slices can overlap (a CRITICAL finding appears in both if minSeverity <= CRITICAL).
func (sf *SeverityFilter) FilterFindings(findings []fetchers.Finding) (toAlert, toEscalate []fetchers.Finding) {
	for _, f := range findings {
		if sf.ShouldAlert(f) {
			toAlert = append(toAlert, f)
		}
		if sf.ShouldEscalate(f) {
			toEscalate = append(toEscalate, f)
		}
	}
	return
}
