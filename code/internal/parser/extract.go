package parser

import "regexp"

// cveRegex matches standard CVE identifiers (CVE-YEAR-ID, 4–7 digit ID part).
var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// ExtractCVEIDs extracts all unique CVE identifiers from an arbitrary text string.
// Useful for sources (e.g., Node.js RSS, vendor advisories) that embed CVE IDs
// in prose or description fields rather than structured data.
func ExtractCVEIDs(text string) []string {
	matches := cveRegex.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	// Deduplicate while preserving order.
	seen := make(map[string]struct{}, len(matches))
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m]; !ok {
			seen[m] = struct{}{}
			result = append(result, m)
		}
	}
	return result
}

// FirstCVEID returns the first CVE ID found in the text, or an empty string.
func FirstCVEID(text string) string {
	return cveRegex.FindString(text)
}
