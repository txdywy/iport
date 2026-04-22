# Testing Patterns

**Analysis Date:** 2026-04-22

## Test Framework

**Runner:**
- Go standard library `testing` package.

**Assertion Library:**
- None; standard library `if` checks with `t.Fatalf` or `t.Errorf`.

**Run Commands:**
```bash
go test ./...              # Run all tests
go test -v ./...           # Verbose mode
go test -cover ./...       # Coverage
```

## Test File Organization

**Location:**
- Co-located with source code: `[package]/[file]_test.go` for every `[package]/[file].go`.

**Naming:**
- `*_test.go` suffix.

## Test Structure

**Suite Organization:**
Table-driven testing is the preferred pattern for unit tests.

```go
func TestParseTarget(t *testing.T) {
	tests := []struct {
		raw      string
		scheme   string
		// ... fields
	}{
		{"example.com", "https", ...},
	}

	for _, tt := range tests {
		got, err := ParseTarget(tt.raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", tt.raw, err)
		}
		// ... assertions
	}
}
```

## Mocking

**Framework:** Manual interface mocking or simple stubbing if required.

## Test Types

**Unit Tests:**
- Primary test method for most logic.

---

*Testing analysis: 2026-04-22*
