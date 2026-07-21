package fetchers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/parser"
	"golang.org/x/mod/modfile"
)

const osvQueryBatchAPI = "https://api.osv.dev/v1/querybatch"

type OSVGoModFetcher struct {
	name   string
	path   string
	client *http.Client
}

func NewOSVGoModFetcher(name, path string) *OSVGoModFetcher {
	return &OSVGoModFetcher{
		name: name,
		path: path,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (f *OSVGoModFetcher) Name() string { return f.name }

type osvBatchQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvBatchQuery struct {
	Queries []osvBatchQueryRequest `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvResponse `json:"results"`
}

func (f *OSVGoModFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("read go.mod file: %w", err)
	}

	parsedFile, err := modfile.Parse(f.path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod file: %w", err)
	}

	if len(parsedFile.Require) == 0 {
		return nil, nil
	}

	var reqBody osvBatchQuery
	for _, req := range parsedFile.Require {
		reqBody.Queries = append(reqBody.Queries, osvBatchQueryRequest{
			Package: osvPackage{
				Name:      req.Mod.Path,
				Ecosystem: "Go",
			},
			Version: req.Mod.Version,
		})
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal batch query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryBatchAPI, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute batch request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv batch returned HTTP %d", resp.StatusCode)
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}

	var findings []Finding
	for _, res := range result.Results {
		for _, v := range res.Vulns {
			f2, ok := f.toFinding(v)
			if ok {
				findings = append(findings, f2)
			}
		}
	}

	slog.Info("osv_gomod fetch complete", "source", f.name, "dependencies_scanned", len(reqBody.Queries), "findings", len(findings))
	return findings, nil
}

func (f *OSVGoModFetcher) toFinding(v osvVuln) (Finding, bool) {
	cveID := extractCVEFromAliases(v.Aliases)
	if cveID == "" {
		cveID = parser.FirstCVEID(v.Summary + " " + v.Details)
	}
	if cveID == "" {
		cveID = v.ID
	}

	published := parseOSVTime(v.Published)

	severity := SeverityUnknown
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		severity = parser.NormalizeSeverityString(v.DatabaseSpecific.Severity)
	} else if v.EcosystemSpecific != nil && v.EcosystemSpecific.Severity != "" {
		severity = parser.NormalizeSeverityString(v.EcosystemSpecific.Severity)
	}

	affectedVer := extractAffectedVersion(v.Affected)
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
		Source:          f.name,
		Technology:      "Alert App (Go)",
		CVEID:           cveID,
		Description:     desc,
		Severity:        severity,
		URL:             url,
		Published:       published,
		AffectedVersion: affectedVer,
		FixedVersion:    fixedVer,
	}, true
}
