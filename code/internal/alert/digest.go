package alert

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

// DigestSender sends a weekly rollup summary of all findings from the past 7 days.
// The digest always covers all severities regardless of MIN_ALERT_SEVERITY,
// since it is meant to be a complete picture (§3.11).
type DigestSender struct {
	client *TeamsClient
}

// NewDigestSender creates a digest sender using the given Teams client.
// The client should point to WEEKLY_DIGEST_WEBHOOK_URL if set, or fall back
// to the main TEAMS_WEBHOOK_URL.
func NewDigestSender(client *TeamsClient) *DigestSender {
	return &DigestSender{client: client}
}

// Send computes and posts the weekly digest to Teams.
func (d *DigestSender) Send(ctx context.Context, findings []fetchers.StoredFinding, since time.Time) error {
	if !d.client.IsConfigured() {
		slog.Info("weekly digest skipped — no webhook URL configured")
		return nil
	}
	if len(findings) == 0 {
		slog.Info("weekly digest: no findings in the past 7 days")
		// Send a "no findings" digest so the channel knows the system is healthy.
	}

	card := d.buildDigestCard(findings, since)
	if err := d.client.SendMessage(ctx, card); err != nil {
		return fmt.Errorf("send weekly digest: %w", err)
	}
	slog.Info("weekly digest sent", "findings_count", len(findings), "since", since.Format("2006-01-02"))
	return nil
}

func (d *DigestSender) buildDigestCard(findings []fetchers.StoredFinding, since time.Time) teamsMessageCard {
	// Count by severity.
	sevCounts := map[fetchers.Severity]int{}
	// Count by technology.
	techCounts := map[string]int{}

	for _, sf := range findings {
		sevCounts[sf.Severity]++
		techCounts[sf.Technology]++
	}

	periodStr := fmt.Sprintf("%s – %s",
		since.Format("Jan 02"),
		time.Now().Format("Jan 02, 2006"),
	)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**Period:** %s\n\n", periodStr))
	sb.WriteString(fmt.Sprintf("**Total findings:** %d\n\n", len(findings)))

	// Severity breakdown.
	if len(findings) > 0 {
		sb.WriteString("**By severity:**\n")
		for _, sev := range []fetchers.Severity{fetchers.SeverityCritical, fetchers.SeverityHigh, fetchers.SeverityMedium, fetchers.SeverityLow, fetchers.SeverityUnknown} {
			if n := sevCounts[sev]; n > 0 {
				sb.WriteString(fmt.Sprintf("- %s: **%d**\n", sev, n))
			}
		}
		sb.WriteString("\n**By technology:**\n")
		for tech, n := range techCounts {
			sb.WriteString(fmt.Sprintf("- %s: **%d**\n", tech, n))
		}
	} else {
		sb.WriteString("✅ No new vulnerability findings this week.")
	}

	return teamsMessageCard{
		Type:       "MessageCard",
		Context:    "http://schema.org/extensions",
		ThemeColor: "6366f1",
		Summary:    fmt.Sprintf("📊 Weekly Security Digest — %s", periodStr),
		Title:      fmt.Sprintf("📊 Weekly Security Digest — %s", periodStr),
		Text:       sb.String(),
	}
}
