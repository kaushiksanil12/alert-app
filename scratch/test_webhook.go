package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/alert"
	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

func main() {
	url := os.Getenv("TEAMS_WEBHOOK_URL")
	if url == "" {
		log.Fatal("TEAMS_WEBHOOK_URL is empty! Did you source the .env file?")
	}
	if url == "https://outlook.office.com/webhook/YOUR_WEBHOOK_URL_HERE" {
		log.Fatal("TEAMS_WEBHOOK_URL is still the default example value! Please add your real webhook URL to .env")
	}

	client := alert.NewTeamsClient(url)

	findings := []fetchers.Finding{
		{
			CVEID:       "CVE-TEST-9999",
			Technology:  "Security-App",
			Severity:    fetchers.SeverityCritical,
			Description: "🚀 This is a test critical alert triggered manually to verify that your Microsoft Teams webhook integration is functioning correctly!",
			URL:         "https://example.com/test",
			Source:      "manual_test",
			Published:   time.Now().Add(-24 * time.Hour),
		},
	}

	fmt.Println("Sending test alert to Teams webhook:", url)
	err := client.SendFindings(context.Background(), findings)
	if err != nil {
		log.Fatalf("Failed to send alert: %v", err)
	}

	fmt.Println("✅ Alert successfully sent to Teams!")
}
