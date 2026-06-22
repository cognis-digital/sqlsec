// Package sqlsec is a Go port of the core sqlsec check: a passive,
// offline heuristic that flags unsafe SQL-query construction in source text.
//
// It mirrors the highest-signal rules from the Python reference
// implementation (SQL001 concatenation, SQL002 f/template interpolation,
// SQL003 printf-style formatting) so the same finding ids surface across
// language ecosystems. Defensive / educational scope only; it never executes
// anything and makes no network calls.
//
// Original work by Cognis Digital.
package sqlsec

import (
	"regexp"
	"strings"
)

// Severity levels, matching the reference tool's vocabulary.
type Severity string

const (
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Finding is one detected unsafe pattern at a 1-based line number.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	Snippet  string   `json:"snippet"`
}

var sqlKeywords = regexp.MustCompile(
	`(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|` +
		`CREATE\s+TABLE|ALTER\s+TABLE|FROM|WHERE|VALUES|JOIN|UNION|` +
		`TRUNCATE|GRANT|REVOKE)\b`)

// looksLikeSQL reports whether a line plausibly contains a SQL fragment.
func looksLikeSQL(line string) bool {
	return sqlKeywords.MatchString(line)
}

type rule struct {
	id       string
	severity Severity
	pattern  *regexp.Regexp
	message  string
	needsSQL bool
}

var rules = []rule{
	{
		id:       "SQL001",
		severity: High,
		pattern:  regexp.MustCompile(`["'].*?["']\s*\+\s*\w|\w\s*\+\s*["'].*?["']`),
		message:  "SQL query built by string concatenation with a variable",
		needsSQL: true,
	},
	{
		// Go-style fmt.Sprintf / template interpolation of a value into SQL.
		id:       "SQL002",
		severity: High,
		pattern:  regexp.MustCompile(`(?i)(Sprintf|Sprint)\s*\(\s*["'].*?(%[sdvq]|\{).*?["']`),
		message:  "value interpolated into a SQL statement via Sprintf/format",
		needsSQL: true,
	},
	{
		id:       "SQL003",
		severity: High,
		pattern:  regexp.MustCompile(`["'].*?%[sd].*?["']\s*%\s*[\w(]`),
		message:  "SQL string assembled with printf-style formatting",
		needsSQL: true,
	},
}

// ScanText applies the rule set to source text line by line.
func ScanText(text string) []Finding {
	var findings []Finding
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		for _, r := range rules {
			if r.needsSQL && !looksLikeSQL(line) {
				continue
			}
			if r.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:   r.id,
					Severity: r.severity,
					Line:     i + 1,
					Message:  r.message,
					Snippet:  strings.TrimSpace(line),
				})
			}
		}
	}
	return findings
}
