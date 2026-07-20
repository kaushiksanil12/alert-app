// Package fetchers defines the Fetcher interface and re-exports data types
// from internal/types for convenience. All fetcher implementations live in
// this package and return types.Finding slices.
package fetchers

import (
	"context"

	"github.com/kaushik/vuln-alert-service/internal/types"
)

// Re-export types from the types package so callers only need to import fetchers.
type Finding = types.Finding
type StoredFinding = types.StoredFinding
type Severity = types.Severity

const (
	SeverityUnknown  = types.SeverityUnknown
	SeverityLow      = types.SeverityLow
	SeverityMedium   = types.SeverityMedium
	SeverityHigh     = types.SeverityHigh
	SeverityCritical = types.SeverityCritical
)

var SeverityOrder = types.SeverityOrder

// Fetcher is the common interface all data source fetchers must implement.
type Fetcher interface {
	Name() string
	Fetch(ctx context.Context) ([]Finding, error)
}
