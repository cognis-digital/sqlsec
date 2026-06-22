package sqlsec

import "testing"

func hasRule(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestConcatFlaggedSQL001(t *testing.T) {
	src := `query := "SELECT * FROM users WHERE id = " + userID`
	fs := ScanText(src)
	if !hasRule(fs, "SQL001") {
		t.Fatalf("expected SQL001, got %+v", fs)
	}
}

func TestSprintfFlaggedSQL002(t *testing.T) {
	src := `q := fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", name)`
	fs := ScanText(src)
	if !hasRule(fs, "SQL002") {
		t.Fatalf("expected SQL002, got %+v", fs)
	}
}

func TestPercentFormatSQL003(t *testing.T) {
	src := `q = "SELECT * FROM t WHERE id = %s" % value`
	fs := ScanText(src)
	if !hasRule(fs, "SQL003") {
		t.Fatalf("expected SQL003, got %+v", fs)
	}
}

func TestNonSQLConcatIgnored(t *testing.T) {
	src := `greeting := "hello " + name`
	if fs := ScanText(src); len(fs) != 0 {
		t.Fatalf("expected no findings for non-SQL concat, got %+v", fs)
	}
}

func TestParameterizedIsClean(t *testing.T) {
	src := `db.Query("SELECT * FROM users WHERE id = ?", userID)`
	if fs := ScanText(src); len(fs) != 0 {
		t.Fatalf("expected clean parameterized query, got %+v", fs)
	}
}

func TestLineNumbersReported(t *testing.T) {
	src := "package main\n\nq := \"SELECT * FROM t WHERE x=\" + v"
	fs := ScanText(src)
	if len(fs) == 0 || fs[0].Line != 3 {
		t.Fatalf("expected finding on line 3, got %+v", fs)
	}
}

func TestEmptyInput(t *testing.T) {
	if fs := ScanText(""); len(fs) != 0 {
		t.Fatalf("expected no findings on empty input, got %+v", fs)
	}
}
