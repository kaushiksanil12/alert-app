package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/parser"
)

const (
	nvdAPIBase        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdResultsPerPage = 100
	// NVD rate limits: 5 req/30s without key, 50 req/10s with key.
	// We sleep between paginated requests to stay within limits.
	nvdRateSleepNoKey  = 7 * time.Second // ~4 req/30s (safe buffer)
	nvdRateSleepWithKey = 250 * time.Millisecond
)

// NVDFetcher queries the NIST NVD CVE API v2 using a keyword search.
// Used for: Java/OpenJDK, C++/GCC, Docker, Git, GitLab, AWS, GCP, SonarQube,
//           Python/CPython, Azure, Kubernetes.
type NVDFetcher struct {
	name        string
	technology  string
	keyword     string
	minSeverity string // optional per-source override; empty = use global MIN_ALERT_SEVERITY
	apiKey      string
	client      *http.Client
}

// NewNVDFetcher creates a new NVD keyword-search fetcher.
// apiKey may be empty; if set, it is added to the request header (never logged).
func NewNVDFetcher(name, technology, keyword, minSeverity, apiKey string) *NVDFetcher {
	return &NVDFetcher{
		name:        name,
		technology:  technology,
		keyword:     keyword,
		minSeverity: minSeverity,
		apiKey:      apiKey,
		client:      &http.Client{Timeout: 45 * time.Second},
	}
}

func (f *NVDFetcher) Name() string { return f.name }

func (f *NVDFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	var all []Finding
	startIndex := 0

	for {
		batch, total, err := f.fetchPage(ctx, startIndex)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)

		next := startIndex + nvdResultsPerPage
		if next >= total || len(batch) == 0 {
			break
		}
		startIndex = next

		// Rate-limit between paginated calls.
		sleep := nvdRateSleepWithKey
		if f.apiKey == "" {
			sleep = nvdRateSleepNoKey
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}

	slog.Info("nvd fetch complete", "source", f.name, "findings", len(all))
	return all, nil
}

func (f *NVDFetcher) fetchPage(ctx context.Context, startIndex int) ([]Finding, int, error) {
	params := url.Values{}
	params.Set("keywordSearch", f.keyword)
	params.Set("resultsPerPage", fmt.Sprintf("%d", nvdResultsPerPage))
	params.Set("startIndex", fmt.Sprintf("%d", startIndex))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nvdAPIBase+"?"+params.Encode(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if f.apiKey != "" {
		req.Header.Set("apiKey", f.apiKey) // NVD API key header (never logged)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, 0, fmt.Errorf("nvd rate limited (HTTP %d) — add NVD_API_KEY to raise limits", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, 0, fmt.Errorf("nvd HTTP %d: %s", resp.StatusCode, b)
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, 0, fmt.Errorf("nvd decode response: %w", err)
	}

	findings := make([]Finding, 0, len(result.Vulnerabilities))
	for _, vw := range result.Vulnerabilities {
		finding, ok := f.toFinding(vw.CVE)
		if !ok {
			continue
		}
		findings = append(findings, finding)
	}

	return findings, result.TotalResults, nil
}

func (f *NVDFetcher) toFinding(cve nvdCVE) (Finding, bool) {
	if cve.ID == "" {
		return Finding{}, false
	}

	sev := f.extractSeverity(cve)

	// If source has a min_severity filter, skip below that threshold.
	if f.minSeverity != "" {
		minSev := parser.NormalizeSeverityString(f.minSeverity)
		if !sev.AtLeast(minSev) {
			return Finding{}, false
		}
	}

	desc := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc = parser.Sanitize(d.Value)
			break
		}
	}

	url := ""
	if len(cve.References) > 0 {
		url = cve.References[0].URL
	}

	published := parseNVDTime(cve.Published)

	return Finding{
		Source:      f.name,
		Technology:  f.technology,
		CVEID:       cve.ID,
		Severity:    sev,
		Description: desc,
		URL:         url,
		Published:   published,
		// FixedVersion: NVD doesn't provide structured fix versions; left empty per §3.13
	}, true
}

func (f *NVDFetcher) extractSeverity(cve nvdCVE) Severity {
	// Prefer CVSS v3.1, then v3.0, then v2.
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		m := cve.Metrics.CVSSMetricV31[0]
		if m.CVSSData.BaseSeverity != "" {
			return parser.NormalizeSeverityString(m.CVSSData.BaseSeverity)
		}
		return parser.NormalizeCVSSScore(m.CVSSData.BaseScore)
	}
	if len(cve.Metrics.CVSSMetricV30) > 0 {
		m := cve.Metrics.CVSSMetricV30[0]
		if m.CVSSData.BaseSeverity != "" {
			return parser.NormalizeSeverityString(m.CVSSData.BaseSeverity)
		}
		return parser.NormalizeCVSSScore(m.CVSSData.BaseScore)
	}
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		return parser.NormalizeCVSSScore(cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore)
	}
	return SeverityUnknown
}

func parseNVDTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ─── NVD API v2 response types ────────────────────────────────────────────────

type nvdResponse struct {
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string       `json:"id"`
	Descriptions []nvdDesc    `json:"descriptions"`
	Metrics      nvdMetrics   `json:"metrics"`
	References   []nvdRef     `json:"references"`
	Published    string       `json:"published"`
	LastModified string       `json:"lastModified"`
}

type nvdDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CVSSMetricV31 []nvdCVSSMetric   `json:"cvssMetricV31"`
	CVSSMetricV30 []nvdCVSSMetric   `json:"cvssMetricV30"`
	CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdCVSSMetricV2 struct {
	BaseSeverity string      `json:"baseSeverity"`
	CVSSData     nvdCVSSData `json:"cvssData"`
}

type nvdRef struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}
