package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SourceConfig defines how to fetch vulnerabilities for one tracked technology.
// All source-specific fields (ecosystem, keyword, url) are optional depending on type.
type SourceConfig struct {
	Name        string `yaml:"name"`                   // unique ID, used as store key prefix
	Technology  string `yaml:"technology"`             // display name for alerts and dashboard
	Type        string `yaml:"type"`                   // osv | nvd | vendor_rss | osv_gomod
	Keyword     string `yaml:"keyword,omitempty"`      // For NVD searches
	Ecosystem   string `yaml:"ecosystem,omitempty"`    // For OSV searches
	Package     string `yaml:"package,omitempty"`      // For OSV searches
	URL         string `yaml:"url,omitempty"`          // For Vendor RSS
	Path        string `yaml:"path,omitempty"`         // For local file scans (like go.mod)
	Format      string `yaml:"format,omitempty"`       // For Vendor RSS
	MinSeverity string `yaml:"min_severity,omitempty"` // Filter out LOW/MEDIUM
}

// SourcesFile is the top-level structure of sources.yaml.
type SourcesFile struct {
	Sources []SourceConfig `yaml:"sources"`
}

// AppConfig holds all runtime configuration derived from environment variables
// and the sources file. Secrets are loaded here but must never be logged.
type AppConfig struct {
	// Secrets — never log these values
	TeamsWebhookURL        string
	NVDAPIKey              string
	GitHubToken            string
	CriticalWebhookURL     string
	WeeklyDigestWebhookURL string

	// Non-secret config
	TZ                    string
	DataDir               string
	Port                  string
	MinAlertSeverity      string
	WeeklyDigestDay       string
	FailureAlertThreshold int
	RetentionDays         int
	LogRetentionDays      int

	// Derived
	Location *time.Location
	Sources  []SourceConfig
}

// Load reads configuration from environment variables and the given sources YAML file.
func Load(sourcesPath string) (*AppConfig, error) {
	cfg := &AppConfig{
		TeamsWebhookURL:        os.Getenv("TEAMS_WEBHOOK_URL"),
		NVDAPIKey:              os.Getenv("NVD_API_KEY"),
		GitHubToken:            os.Getenv("GITHUB_TOKEN"),
		CriticalWebhookURL:     os.Getenv("CRITICAL_WEBHOOK_URL"),
		WeeklyDigestWebhookURL: os.Getenv("WEEKLY_DIGEST_WEBHOOK_URL"),

		TZ:               envOr("TZ", "Asia/Kolkata"),
		DataDir:          envOr("DATA_DIR", "/data"),
		Port:             envOr("PORT", "8080"),
		MinAlertSeverity: envOr("MIN_ALERT_SEVERITY", "LOW"),
		WeeklyDigestDay:  envOr("WEEKLY_DIGEST_DAY", "Monday"),

		FailureAlertThreshold: envInt("FAILURE_ALERT_THRESHOLD", 3),
		RetentionDays:         envInt("RETENTION_DAYS", 30),
		LogRetentionDays:      envInt("LOG_RETENTION_DAYS", 30),
	}

	// Load timezone — must succeed or fail fast so local-midnight scheduling works.
	loc, err := time.LoadLocation(cfg.TZ)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone %q: %w", cfg.TZ, err)
	}
	cfg.Location = loc

	// Load sources.yaml.
	data, err := os.ReadFile(sourcesPath)
	if err != nil {
		return nil, fmt.Errorf("read sources file %q: %w", sourcesPath, err)
	}
	var sf SourcesFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse sources file: %w", err)
	}
	if len(sf.Sources) == 0 {
		return nil, fmt.Errorf("sources file has no entries — check %s", sourcesPath)
	}
	cfg.Sources = sf.Sources

	return cfg, nil
}

// RedactedSecrets returns a map of config keys to "[REDACTED]" for safe structured logging.
func (c *AppConfig) RedactedSecrets() map[string]string {
	redact := func(v string) string {
		if v == "" {
			return "(not set)"
		}
		return "[REDACTED]"
	}
	return map[string]string{
		"TEAMS_WEBHOOK_URL":         redact(c.TeamsWebhookURL),
		"NVD_API_KEY":               redact(c.NVDAPIKey),
		"GITHUB_TOKEN":              redact(c.GitHubToken),
		"CRITICAL_WEBHOOK_URL":      redact(c.CriticalWebhookURL),
		"WEEKLY_DIGEST_WEBHOOK_URL": redact(c.WeeklyDigestWebhookURL),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}
