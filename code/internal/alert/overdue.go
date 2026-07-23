// Package alert handles sending notifications (e.g. to Teams).
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/store"
)

// OverdueAlerter handles sending notifications for overdue tasks.
type OverdueAlerter struct {
	webhookURL string
	httpClient *http.Client
}

// NewOverdueAlerter creates a new overdue alerter.
func NewOverdueAlerter(webhookURL string) *OverdueAlerter {
	return &OverdueAlerter{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// AlertOverdue formats and sends an alert to Teams for overdue tasks.
func (a *OverdueAlerter) AlertOverdue(tasks []store.Task) error {
	if len(tasks) == 0 {
		return nil
	}
	if a.webhookURL == "" {
		slog.Info("no teams webhook configured; skipping overdue alert", "overdue_count", len(tasks))
		return nil
	}

	// Group tasks by assignee.
	byAssignee := make(map[string][]store.Task)
	for _, t := range tasks {
		byAssignee[t.AssignedTo] = append(byAssignee[t.AssignedTo], t)
	}

	var facts []map[string]string
	for assignee, userTasks := range byAssignee {
		var lines []string
		for _, t := range userTasks {
			daysOverdue := int(time.Since(*t.DueDate).Hours() / 24)
			lines = append(lines, fmt.Sprintf("- **%s** (%s) - %d days overdue", t.CVEID, t.Technology, daysOverdue))
		}
		facts = append(facts, map[string]string{
			"name":  assignee,
			"value": strings.Join(lines, "\n"),
		})
	}

	msg := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "ff6b00", // High severity orange
		"summary":    "Overdue Vulnerability Tasks",
		"title":      fmt.Sprintf("⚠️ %d Vulnerability Tasks Overdue", len(tasks)),
		"text":       "The following vulnerability tasks are past their assigned due date and require immediate attention.",
		"sections": []map[string]any{
			{
				"facts": facts,
			},
		},
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal teams msg: %w", err)
	}

	resp, err := a.httpClient.Post(a.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post to teams: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("teams returned status %d", resp.StatusCode)
	}

	slog.Info("sent overdue alert to teams", "overdue_count", len(tasks))
	return nil
}
