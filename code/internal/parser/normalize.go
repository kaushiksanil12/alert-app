package parser

import (
	"strconv"
	"strings"

	"github.com/kaushik/vuln-alert-service/internal/types"
)

// NormalizeSeverityString converts a severity label from any source into the
// internal enum. Handles OSV, NVD, npm, GitHub Advisory, and vendor feeds.
func NormalizeSeverityString(s string) types.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH", "IMPORTANT":
		return types.SeverityHigh
	case "MEDIUM", "MODERATE", "AVERAGE":
		return types.SeverityMedium
	case "LOW", "MINOR", "INFORMATIONAL", "INFO":
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

// NormalizeCVSSScore converts a numeric CVSS base score into the internal enum.
// Uses CVSS v3.1 qualitative rating scale per NIST guidelines.
func NormalizeCVSSScore(score float64) types.Severity {
	switch {
	case score >= 9.0:
		return types.SeverityCritical
	case score >= 7.0:
		return types.SeverityHigh
	case score >= 4.0:
		return types.SeverityMedium
	case score > 0.0:
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

// NormalizeCVSSScoreStr parses and normalizes a CVSS score string (e.g. "7.5").
func NormalizeCVSSScoreStr(s string) types.Severity {
	score, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return types.SeverityUnknown
	}
	return NormalizeCVSSScore(score)
}

// BestSeverity returns the highest of two severity values.
func BestSeverity(a, b types.Severity) types.Severity {
	if types.SeverityOrder[a] >= types.SeverityOrder[b] {
		return a
	}
	return b
}

// SeverityColor returns a CSS color hex for the given severity, used in the dashboard.
func SeverityColor(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "#ef4444"
	case types.SeverityHigh:
		return "#f97316"
	case types.SeverityMedium:
		return "#eab308"
	case types.SeverityLow:
		return "#22c55e"
	default:
		return "#6b7280"
	}
}
