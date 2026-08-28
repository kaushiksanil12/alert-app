package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

// TeamsClient sends vulnerability findings to Microsoft Teams via incoming webhook.
// Supports the legacy MessageCard format for broadest compatibility.
type TeamsClient struct {
	webhookURL string // never logged
	client     *http.Client
}

// NewTeamsClient creates a new Teams webhook client.
// webhookURL is stored but never logged — it is a secret.
func NewTeamsClient(webhookURL string) *TeamsClient {
	return &TeamsClient{
		webhookURL: webhookURL,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// IsConfigured returns true if a webhook URL is set.
func (t *TeamsClient) IsConfigured() bool {
	return t.webhookURL != ""
}

// SendFindings posts a batched message for all findings in a single Teams POST.
// Same-day findings are batched into one message to avoid channel spam (§3.5).
func (t *TeamsClient) SendFindings(ctx context.Context, findings []fetchers.Finding) error {
	if len(findings) == 0 || !t.IsConfigured() {
		return nil
	}

	card := t.buildMessageCard(findings)
	return t.post(ctx, card)
}

// SendMetaAlert posts a meta-alert about a failing source.
func (t *TeamsClient) SendMetaAlert(ctx context.Context, source string, consecutiveDays int) error {
	if !t.IsConfigured() {
		return nil
	}
	card := teamsMessageCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: "FF6B35",
		Summary:    fmt.Sprintf("⚠️ Source %q has failed for %d consecutive days", source, consecutiveDays),
		Title:      "⚠️ Vulnerability Source Failure Alert",
		Text: fmt.Sprintf(
			"**Source `%s`** has failed to fetch vulnerability data for **%d consecutive days**. "+
				"This may indicate a silent blind spot. Please investigate the source configuration and connectivity.",
			source, consecutiveDays,
		),
	}
	return t.post(ctx, card)
}

// SendMessage posts a raw pre-formatted MessageCard (used by digest).
func (t *TeamsClient) SendMessage(ctx context.Context, card teamsMessageCard) error {
	if !t.IsConfigured() {
		return nil
	}
	return t.post(ctx, card)
}

// buildMessageCard constructs a MessageCard payload for a batch of findings.
func (t *TeamsClient) buildMessageCard(findings []fetchers.Finding) teamsMessageCard {
	severityCounts := map[fetchers.Severity]int{}
	for _, f := range findings {
		severityCounts[f.Severity]++
	}

	summary := fmt.Sprintf("🛡️ %d new security finding(s) detected", len(findings))
	themeColor := severityThemeColor(findings)

	sections := make([]teamsSection, 0, len(findings))
	for i, f := range findings {
		if i >= 20 {
			// Cap at 20 sections to avoid oversized payloads.
			break
		}
		title := fmt.Sprintf("**%s** — %s (Source: %s)", f.CVEID, f.Technology, f.Source)
		if f.URL != "" {
			title = fmt.Sprintf("**[%s](%s)** — %s (Source: %s)", f.CVEID, f.URL, f.Technology, f.Source)
		}

		section := teamsSection{
			ActivityTitle:    title,
			ActivitySubtitle: fmt.Sprintf("Severity: **%s** | Published: %s", f.Severity, formatDate(f.Published)),
			Facts:            buildFacts(f),
			Markdown:         true,
		}
		if f.URL != "" {
			section.PotentialAction = []teamsAction{
				{
					Type: "OpenUri",
					Name: "View Advisory",
					Targets: []teamsActionTarget{
						{OS: "default", URI: f.URL},
					},
				},
			}
		}
		sections = append(sections, section)
	}

	remaining := len(findings) - len(sections)
	text := ""
	if remaining > 0 {
		text = fmt.Sprintf("*...and %d more findings. See the dashboard for the full list.*", remaining)
	}

	return teamsMessageCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: themeColor,
		Summary:    summary,
		Title:      summary,
		Text:       text,
		Sections:   sections,
	}
}

func buildFacts(f fetchers.Finding) []teamsFact {
	facts := []teamsFact{
		{Name: "Technology", Value: f.Technology},
		{Name: "Severity", Value: string(f.Severity)},
		{Name: "Source", Value: f.Source},
	}
	if f.Description != "" {
		desc := f.Description
		if len(desc) > 300 {
			desc = desc[:297] + "..."
		}
		facts = append(facts, teamsFact{Name: "Description", Value: desc})
	}
	// Include fix version only when present — never "unknown" (§3.13)
	if f.FixedVersion != "" {
		facts = append(facts, teamsFact{Name: "Fixed in", Value: f.FixedVersion})
	}
	if !f.Published.IsZero() {
		facts = append(facts, teamsFact{Name: "Published", Value: f.Published.Format("2006-01-02")})
	}
	return facts
}

func severityThemeColor(findings []fetchers.Finding) string {
	highest := fetchers.SeverityUnknown
	for _, f := range findings {
		if fetchers.SeverityOrder[f.Severity] > fetchers.SeverityOrder[highest] {
			highest = f.Severity
		}
	}
	switch highest {
	case fetchers.SeverityCritical:
		return "8B0000" // dark red
	case fetchers.SeverityHigh:
		return "d73a49" // red
	case fetchers.SeverityMedium:
		return "e36209" // orange
	default:
		return "0075CA" // blue
	}
}

func formatDate(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02")
}

func (t *TeamsClient) post(ctx context.Context, card interface{}) error {
	body, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("marshal teams card: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create teams request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("teams post: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	slog.Info("teams message sent", "status", resp.StatusCode)
	return nil
}

// ─── Teams MessageCard types ──────────────────────────────────────────────────

type teamsMessageCard struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor"`
	Summary    string         `json:"summary"`
	Title      string         `json:"title,omitempty"`
	Text       string         `json:"text,omitempty"`
	Sections   []teamsSection `json:"sections,omitempty"`
}

type teamsSection struct {
	ActivityTitle    string         `json:"activityTitle,omitempty"`
	ActivitySubtitle string         `json:"activitySubtitle,omitempty"`
	Facts            []teamsFact    `json:"facts,omitempty"`
	Markdown         bool           `json:"markdown"`
	PotentialAction  []teamsAction  `json:"potentialAction,omitempty"`
}

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsAction struct {
	Type    string              `json:"@type"`
	Name    string              `json:"name"`
	Targets []teamsActionTarget `json:"targets"`
}

type teamsActionTarget struct {
	OS  string `json:"os"`
	URI string `json:"uri"`
}
