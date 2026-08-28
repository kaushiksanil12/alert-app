package fetchers

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/parser"
)

// VendorRSSFetcher fetches vulnerability advisories from vendor-specific feeds.
// Currently supports:
//   - format: "rss"  → Ubuntu USN RSS, Debian DSA RSS (standard RSS 2.0)
//   - format: "json" → Alpine secdb JSON
type VendorRSSFetcher struct {
	name       string
	technology string
	url        string
	format     string // "rss" | "json"
	client     *http.Client
}

// NewVendorRSSFetcher creates a fetcher for a vendor security advisory feed.
func NewVendorRSSFetcher(name, technology, feedURL, format string) *VendorRSSFetcher {
	return &VendorRSSFetcher{
		name:       name,
		technology: technology,
		url:        feedURL,
		format:     format,
		client:     &http.Client{Timeout: 45 * time.Second},
	}
}

func (f *VendorRSSFetcher) Name() string { return f.name }

func (f *VendorRSSFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	switch strings.ToLower(f.format) {
	case "json":
		return f.fetchJSON(ctx)
	default: // "rss" or anything else
		return f.fetchRSS(ctx)
	}
}

// fetchRSS handles standard RSS 2.0 feeds (Ubuntu USN, Debian DSA).
func (f *VendorRSSFetcher) fetchRSS(ctx context.Context) ([]Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("vendor_rss create request: %w", err)
	}
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml, */*")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vendor_rss request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("vendor_rss HTTP %d: %s", resp.StatusCode, b)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("vendor_rss read body: %w", err)
	}

	// Try RSS 2.0.
	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("vendor_rss parse xml: %w", err)
	}

	seen := make(map[string]struct{})
	findings := make([]Finding, 0)

	for _, item := range feed.Channel.Items {
		text := item.Title + " " + item.Description + " " + item.GUID
		cveIDs := parser.ExtractCVEIDs(text)
		published := parseNodeTime(item.PubDate)

		for _, cveID := range cveIDs {
			if _, ok := seen[cveID]; ok {
				continue
			}
			seen[cveID] = struct{}{}
			findings = append(findings, Finding{
				Source:      f.name,
				Technology:  f.technology,
				CVEID:       cveID,
				Severity:    extractVendorSeverity(text),
				Description: parser.Sanitize(item.Title + ": " + item.Description),
				URL:         item.Link,
				Published:   published,
			})
		}
	}

	slog.Info("vendor_rss fetch complete", "source", f.name, "items", len(feed.Channel.Items), "findings", len(findings))
	return findings, nil
}

// fetchJSON handles Alpine secdb JSON format.
// Alpine secdb: https://secdb.alpinelinux.org/edge/main.json
type alpineSecDB struct {
	DistroVersion string        `json:"distroversion"`
	RepoName      string        `json:"reponame"`
	Archs         []alpineArch  `json:"archs"`
}

type alpineArch struct {
	Arch     string        `json:"arch"`
	Packages []alpinePkg   `json:"packages"`
}

type alpinePkg struct {
	Pkg alpinePkgDef `json:"pkg"`
}

type alpinePkgDef struct {
	Name     string              `json:"name"`
	SecFixes map[string][]string `json:"secfixes"` // version → []CVE-ID
}

func (f *VendorRSSFetcher) fetchJSON(ctx context.Context) ([]Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("vendor_json create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vendor_json request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("vendor_json HTTP %d: %s", resp.StatusCode, b)
	}

	var db alpineSecDB
	if err := json.NewDecoder(resp.Body).Decode(&db); err != nil {
		return nil, fmt.Errorf("vendor_json decode: %w", err)
	}

	seen := make(map[string]struct{})
	findings := make([]Finding, 0)

	for _, arch := range db.Archs {
		for _, pkg := range arch.Packages {
			for fixedVer, cves := range pkg.Pkg.SecFixes {
				for _, cveRaw := range cves {
					// Alpine secfixes may contain "CVE-XXXX-YYYY (+ N more)" format.
					cveIDs := parser.ExtractCVEIDs(cveRaw)
					if len(cveIDs) == 0 {
						// The CVE entry itself might just be the ID directly.
						cveIDs = parser.ExtractCVEIDs(cveRaw + " " + cveRaw)
					}

					for _, cveID := range cveIDs {
						if _, ok := seen[cveID]; ok {
							continue
						}
						seen[cveID] = struct{}{}
						findings = append(findings, Finding{
							Source:       f.name,
							Technology:   f.technology,
							CVEID:        cveID,
							Severity:     SeverityUnknown, // Alpine secdb has no severity field
							Description:  fmt.Sprintf("Security fix in package %s", pkg.Pkg.Name),
							URL:          "https://security.alpinelinux.org/vuln/" + cveID,
							Published:    time.Time{}, // No date in secdb
							FixedVersion: fixedVer,
						})
					}
				}
			}
		}
	}

	slog.Info("vendor_json (alpine) fetch complete", "source", f.name, "findings", len(findings))
	return findings, nil
}

// extractVendorSeverity heuristically derives severity from advisory text.
func extractVendorSeverity(text string) Severity {
	upper := strings.ToUpper(text)
	switch {
	case strings.Contains(upper, "CRITICAL"):
		return SeverityCritical
	case strings.Contains(upper, "HIGH"):
		return SeverityHigh
	case strings.Contains(upper, "MEDIUM") || strings.Contains(upper, "MODERATE"):
		return SeverityMedium
	case strings.Contains(upper, "LOW"):
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
