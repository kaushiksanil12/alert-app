package fetchers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/parser"
)

const osvAPIBase = "https://api.osv.dev/v1"

// OSVFetcher queries the OSV.dev REST API for vulnerabilities affecting a specific package.
// Used for: React (npm), Django (PyPI), Spring Boot (Maven), Trivy (Go), ArgoCD (Go).
type OSVFetcher struct {
	name       string
	technology string
	ecosystem  string
	pkg        string
	client     *http.Client
}

// NewOSVFetcher creates a new OSV.dev fetcher for the given package.
func NewOSVFetcher(name, technology, ecosystem, pkg string) *OSVFetcher {
	return &OSVFetcher{
		name:       name,
		technology: technology,
		ecosystem:  ecosystem,
		pkg:        pkg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (f *OSVFetcher) Name() string { return f.name }

func (f *OSVFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	reqBody := osvQueryRequest{
		Package: osvPackage{
			Name:      f.pkg,
			Ecosystem: f.ecosystem,
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("osv marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIBase+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("osv returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv decode response: %w", err)
	}

	findings := make([]Finding, 0, len(result.Vulns))
	for _, v := range result.Vulns {
		f2, ok := f.toFinding(v)
		if !ok {
			continue
		}
		findings = append(findings, f2)
	}

	slog.Info("osv fetch complete", "source", f.name, "vulns_returned", len(result.Vulns), "findings", len(findings))
	return findings, nil
}

func (f *OSVFetcher) toFinding(v osvVuln) (Finding, bool) {
	// Extract CVE ID from aliases list — OSV IDs are usually GHSA-*, we prefer CVE-*.
	cveID := extractCVEFromAliases(v.Aliases)
	if cveID == "" {
		// Fall back to first CVE found in the summary/details text.
		cveID = parser.FirstCVEID(v.Summary + " " + v.Details)
	}
	if cveID == "" {
		// Use the OSV ID itself as the deduplification key if no CVE found.
		cveID = v.ID
	}

	sev := f.extractSeverity(v)
	published := parseOSVTime(v.Published)
	fixedVer := extractFixedVersion(v.Affected)

	desc := parser.Sanitize(v.Summary)
	if desc == "" {
		desc = parser.Sanitize(v.Details)
	}

	url := ""
	for _, ref := range v.References {
		if ref.Type == "ADVISORY" || ref.Type == "WEB" {
			url = ref.URL
			break
		}
	}
	if url == "" && len(v.References) > 0 {
		url = v.References[0].URL
	}

	return Finding{
		Source:       f.name,
		Technology:   f.technology,
		CVEID:        cveID,
		Severity:     sev,
		Description:  desc,
		URL:          url,
		Published:    published,
		FixedVersion: fixedVer,
	}, true
}

func (f *OSVFetcher) extractSeverity(v osvVuln) Severity {
	// 1. Try CVSS v3 numeric score from severity array.
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			// Score field is the CVSS vector string; extract numeric score from database_specific if available.
			break
		}
	}
	// 2. Try database_specific.severity (GitHub Advisory Database uses this).
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		return parser.NormalizeSeverityString(v.DatabaseSpecific.Severity)
	}
	// 3. Try CVSS numeric score from ecosystem-specific data.
	if v.EcosystemSpecific != nil && v.EcosystemSpecific.Severity != "" {
		return parser.NormalizeSeverityString(v.EcosystemSpecific.Severity)
	}
	return SeverityUnknown
}

// extractCVEFromAliases finds the first CVE-prefixed alias in the list.
func extractCVEFromAliases(aliases []string) string {
	for _, a := range aliases {
		if len(a) > 4 && a[:4] == "CVE-" {
			return a
		}
	}
	return ""
}

// extractFixedVersion finds the earliest fixed version from the affected ranges (§3.13).
func extractFixedVersion(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func parseOSVTime(s string) time.Time {
	formats := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05"}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ─── OSV API types (stdlib JSON only, no third-party JSON library) ────────────

type osvQueryRequest struct {
	Package osvPackage `json:"package"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID                string            `json:"id"`
	Aliases           []string          `json:"aliases"`
	Summary           string            `json:"summary"`
	Details           string            `json:"details"`
	Severity          []osvSeverity     `json:"severity"`
	Affected          []osvAffected     `json:"affected"`
	References        []osvReference    `json:"references"`
	Published         string            `json:"published"`
	Modified          string            `json:"modified"`
	DatabaseSpecific  *osvDBSpecific    `json:"database_specific"`
	EcosystemSpecific *osvEcoSpecific   `json:"ecosystem_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"` // CVSS vector string
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvDBSpecific struct {
	Severity string `json:"severity"`
}

type osvEcoSpecific struct {
	Severity string `json:"severity"`
}
