/**
 * TypeScript port of the core sqlsec check: a passive, offline heuristic that
 * flags unsafe SQL-query construction in source text.
 *
 * Mirrors the high-signal rules from the Python reference (SQL001
 * concatenation, SQL002 template-literal interpolation, SQL003 printf-style
 * formatting) so finding ids stay consistent across language ecosystems.
 * Defensive / educational scope only; executes nothing, no network.
 *
 * Original work by Cognis Digital.
 */

export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  ruleId: string;
  severity: Severity;
  line: number; // 1-based
  message: string;
  snippet: string;
}

const SQL_KEYWORDS =
  /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|FROM|WHERE|VALUES|JOIN|UNION|TRUNCATE|GRANT|REVOKE)\b/i;

function looksLikeSql(line: string): boolean {
  return SQL_KEYWORDS.test(line);
}

interface Rule {
  id: string;
  severity: Severity;
  pattern: RegExp;
  message: string;
  needsSql: boolean;
}

const RULES: Rule[] = [
  {
    id: "SQL001",
    severity: "high",
    pattern: /["'].*?["']\s*\+\s*\w|\w\s*\+\s*["'].*?["']/,
    message: "SQL query built by string concatenation with a variable",
    needsSql: true,
  },
  {
    // Template literal interpolation: `... ${value} ...` containing SQL.
    id: "SQL002",
    severity: "high",
    pattern: /`[^`]*\$\{[^}]+\}[^`]*`/,
    message: "value interpolated into a SQL statement via template literal",
    needsSql: true,
  },
  {
    id: "SQL003",
    severity: "high",
    pattern: /["'].*?%[sd].*?["']\s*%\s*[\w(]/,
    message: "SQL string assembled with printf-style formatting",
    needsSql: true,
  },
];

/** Apply the rule set to source text, returning findings line by line. */
export function scanText(text: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");
  lines.forEach((raw, i) => {
    const line = raw.replace(/\r$/, "");
    if (line.trim() === "") return;
    for (const r of RULES) {
      if (r.needsSql && !looksLikeSql(line)) continue;
      if (r.pattern.test(line)) {
        findings.push({
          ruleId: r.id,
          severity: r.severity,
          line: i + 1,
          message: r.message,
          snippet: line.trim(),
        });
      }
    }
  });
  return findings;
}
