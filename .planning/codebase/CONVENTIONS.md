# Coding Conventions

**Analysis Date:** 2026-04-22

## Naming Patterns

**Files:**
- snake_case (e.g., `probe_misc.go`, `webcheck_test.go`)

**Functions:**
- PascalCase for exported functions (e.g., `NormalizeHost`, `ParseTarget`)
- camelCase for unexported/internal functions (e.g., `limitIPs`)

**Variables:**
- camelCase (e.g., `got`, `want`, `tt`, `raw`)

## Code Style

**Formatting:**
- Standard Go formatting (gofmt/goimports)

## Import Organization

**Order:**
1. Standard library imports
2. Third-party imports (if present)
3. Internal package imports

## Error Handling

**Patterns:**
- Standard Go idiom: `if err != nil { ... }` immediately following function calls that return errors.

## Logging

**Framework:** Standard library `log` package (implied usage).

## Comments

**When to Comment:**
- Exported functions have doc comments describing purpose, inputs, and behavior.
- Internal details documented with inline comments where complexity arises.

## Function Design

**Size:** Concise, single-responsibility functions.

**Parameters:** Grouped parameters passed as explicit arguments.

**Return Values:** Standard `(value, error)` signature for operations that can fail.

## Module Design

**Exports:** Minimal set of functions exported to keep internal package API surfaces clean.

---

*Convention analysis: 2026-04-22*
