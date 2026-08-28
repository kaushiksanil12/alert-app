package parser

import "github.com/microcosm-cc/bluemonday"

// policy is a strict HTML sanitizer — strips all tags and attributes.
// Initialized once at package init to reuse across calls (thread-safe).
var policy *bluemonday.Policy

func init() {
	// StrictPolicy strips every HTML tag, leaving plain text only.
	// This is intentionally aggressive: even if an advisory description
	// contains legitimate formatting, we strip it to ensure the dashboard
	// (rendered via html/template, which auto-escapes) never receives raw HTML.
	policy = bluemonday.StrictPolicy()
}

// Sanitize strips all HTML from the input string.
// Must be called on every field sourced from an external feed before storing.
// html/template will still auto-escape the stored text on render, so this
// provides defense-in-depth against stored XSS via compromised upstream feeds.
func Sanitize(html string) string {
	return policy.Sanitize(html)
}
