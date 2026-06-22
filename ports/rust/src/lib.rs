//! Rust port of the core sqlsec check: a passive, offline heuristic that flags
//! unsafe SQL-query construction in source text.
//!
//! Mirrors the high-signal rules from the Python reference (SQL001
//! concatenation, SQL002 format-macro interpolation, SQL003 printf-style
//! formatting) so finding ids stay consistent across language ecosystems.
//! Defensive / educational scope only; executes nothing, no network.
//!
//! Original work by Cognis Digital.

use regex::Regex;

/// Severity vocabulary, matching the reference tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One detected unsafe pattern at a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub line: usize,
    pub message: String,
    pub snippet: String,
}

struct Rule {
    id: &'static str,
    severity: Severity,
    pattern: Regex,
    message: &'static str,
    needs_sql: bool,
}

fn sql_keywords() -> Regex {
    Regex::new(
        r"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|FROM|WHERE|VALUES|JOIN|UNION|TRUNCATE|GRANT|REVOKE)\b",
    )
    .unwrap()
}

fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SQL001",
            severity: Severity::High,
            pattern: Regex::new(r#"["'].*?["']\s*\+\s*\w|\w\s*\+\s*["'].*?["']"#).unwrap(),
            message: "SQL query built by string concatenation with a variable",
            needs_sql: true,
        },
        Rule {
            id: "SQL002",
            severity: Severity::High,
            // format!/write! macro interpolation into SQL text.
            pattern: Regex::new(r#"(?i)format!\s*\(\s*["'].*?(\{|%[sdq]).*?["']"#).unwrap(),
            message: "value interpolated into a SQL statement via format! macro",
            needs_sql: true,
        },
        Rule {
            id: "SQL003",
            severity: Severity::High,
            pattern: Regex::new(r#"["'].*?%[sd].*?["']\s*%\s*[\w(]"#).unwrap(),
            message: "SQL string assembled with printf-style formatting",
            needs_sql: true,
        },
    ]
}

/// Apply the rule set to source text, returning findings line by line.
pub fn scan_text(text: &str) -> Vec<Finding> {
    let kw = sql_keywords();
    let rs = rules();
    let mut findings = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        for r in &rs {
            if r.needs_sql && !kw.is_match(line) {
                continue;
            }
            if r.pattern.is_match(line) {
                findings.push(Finding {
                    rule_id: r.id.to_string(),
                    severity: r.severity,
                    line: i + 1,
                    message: r.message.to_string(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(fs: &[Finding], id: &str) -> bool {
        fs.iter().any(|f| f.rule_id == id)
    }

    #[test]
    fn concat_flagged() {
        let fs = scan_text("let q = \"SELECT * FROM users WHERE id = \" + user_id;");
        assert!(has(&fs, "SQL001"));
    }

    #[test]
    fn format_macro_flagged() {
        let fs = scan_text("let q = format!(\"SELECT * FROM t WHERE n = '{}'\", name);");
        assert!(has(&fs, "SQL002"));
    }

    #[test]
    fn non_sql_concat_ignored() {
        let fs = scan_text("let g = \"hello \" + name;");
        assert!(fs.is_empty());
    }

    #[test]
    fn parameterized_is_clean() {
        let fs = scan_text("client.query(\"SELECT * FROM users WHERE id = $1\", &[&id]);");
        assert!(fs.is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(scan_text("").is_empty());
    }

    #[test]
    fn line_number_reported() {
        let fs = scan_text("fn main() {}\n\nlet q = \"SELECT x FROM t WHERE y=\" + v;");
        assert_eq!(fs[0].line, 3);
    }
}
