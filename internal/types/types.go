// Package types defines shared data types used across the vulnerability alert service.
// It has no internal dependencies, making it safe to import from any package.
package types

import "time"

// Severity represents a normalized vulnerability severity level.
type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// SeverityOrder maps severity levels to a numeric value for comparison.
var SeverityOrder = map[Severity]int{
	SeverityUnknown:  0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return SeverityOrder[s] >= SeverityOrder[min]
}

// Finding represents a single vulnerability finding from any source.
type Finding struct {
	Source       string
	Technology   string
	CVEID        string
	Severity     Severity
	Description  string    // sanitized — no raw HTML
	URL          string
	Published       time.Time
	AffectedVersion string    // version(s) in which vulnerability was detected
	FixedVersion    string    // best-effort; empty if not available from source (§3.13)
}

// StoredFinding wraps a Finding with state tracked only in the local store.
type StoredFinding struct {
	Finding
	FirstSeen      time.Time
	Acknowledged   bool
	AcknowledgedAt *time.Time
}

// DeduplicateKey returns the canonical composite key for this finding.
func (f Finding) DeduplicateKey() string {
	return f.Source + "\x00" + f.CVEID
}
