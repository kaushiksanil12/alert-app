package fetchers

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/parser"
)

// NodeJSRSSFetcher fetches Node.js core security advisories from the official RSS/Atom feed.
// URL: https://nodejs.org/en/feed/vulnerability.xml
type NodeJSRSSFetcher struct {
	name       string
	technology string
	url        string
	client     *http.Client
}

// NewNodeJSRSSFetcher creates a fetcher for the Node.js security advisory feed.
func NewNodeJSRSSFetcher(name, technology, url string) *NodeJSRSSFetcher {
	return &NodeJSRSSFetcher{
		name:       name,
		technology: technology,
		url:        url,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *NodeJSRSSFetcher) Name() string { return f.name }

func (f *NodeJSRSSFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("nodejs_rss create request: %w", err)
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nodejs_rss request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("nodejs_rss HTTP %d: %s", resp.StatusCode, b)
	}

	// Try Atom format first (Node.js uses Atom).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("nodejs_rss read body: %w", err)
	}

	// Detect format from content.
	bodyStr := string(body)
	if strings.Contains(bodyStr, "<feed") {
		return f.parseAtom(body)
	}
	return f.parseRSS(body)
}

// parseAtom parses an Atom feed (Node.js official format).
func (f *NodeJSRSSFetcher) parseAtom(body []byte) ([]Finding, error) {
	var feed atomFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("nodejs_rss parse atom: %w", err)
	}

	findings := make([]Finding, 0, len(feed.Entries))
	seen := make(map[string]struct{})

	for _, entry := range feed.Entries {
		text := entry.Title + " " + entry.Summary + " " + entry.Content
		cveIDs := parser.ExtractCVEIDs(text)

		published := parseNodeTime(entry.Published)
		if published.IsZero() {
			published = parseNodeTime(entry.Updated)
		}

		link := entry.Link.Href
		desc := parser.Sanitize(entry.Summary)
		if desc == "" {
			desc = parser.Sanitize(entry.Title)
		}

		// Emit one Finding per CVE ID found in the entry.
		for _, cveID := range cveIDs {
			if _, ok := seen[cveID]; ok {
				continue
			}
			seen[cveID] = struct{}{}

			findings = append(findings, Finding{
				Source:      f.name,
				Technology:  f.technology,
				CVEID:       cveID,
				Severity:    extractNodeSeverity(entry.Title + " " + entry.Summary),
				Description: desc,
				URL:         link,
				Published:   published,
			})
		}

		// If no CVE IDs found but entry looks advisory-like, use the entry ID.
		if len(cveIDs) == 0 && strings.Contains(strings.ToLower(entry.Title), "vulnerab") {
			entryID := parser.Sanitize(entry.ID)
			if entryID == "" {
				entryID = entry.Link.Href
			}
			if entryID != "" {
				if _, ok := seen[entryID]; !ok {
					seen[entryID] = struct{}{}
					findings = append(findings, Finding{
						Source:      f.name,
						Technology:  f.technology,
						CVEID:       entryID,
						Severity:    SeverityUnknown,
						Description: desc,
						URL:         link,
						Published:   published,
					})
				}
			}
		}
	}

	slog.Info("nodejs_rss fetch complete", "source", f.name, "entries", len(feed.Entries), "findings", len(findings))
	return findings, nil
}

// parseRSS parses a standard RSS 2.0 feed.
func (f *NodeJSRSSFetcher) parseRSS(body []byte) ([]Finding, error) {
	var feed rssFeed
	if err := xml.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("nodejs_rss parse rss: %w", err)
	}

	findings := make([]Finding, 0)
	seen := make(map[string]struct{})

	for _, item := range feed.Channel.Items {
		text := item.Title + " " + item.Description
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
				Severity:    extractNodeSeverity(text),
				Description: parser.Sanitize(item.Description),
				URL:         item.Link,
				Published:   published,
			})
		}
	}

	slog.Info("nodejs_rss (rss format) fetch complete", "source", f.name, "findings", len(findings))
	return findings, nil
}

// extractNodeSeverity heuristically derives severity from advisory text.
func extractNodeSeverity(text string) Severity {
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

func parseNodeTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"2006-01-02",
	}
	s = strings.TrimSpace(s)
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ─── XML types (stdlib encoding/xml only) ─────────────────────────────────────

type atomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title     string   `xml:"title"`
	Link      atomLink `xml:"link"`
	Published string   `xml:"published"`
	Updated   string   `xml:"updated"`
	Summary   string   `xml:"summary"`
	Content   string   `xml:"content"`
	ID        string   `xml:"id"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
}

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}
