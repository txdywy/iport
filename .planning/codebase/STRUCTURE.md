# Codebase Structure

**Analysis Date:** 2026-04-22

## Directory Layout

```
iport/
├── cmd/
│   └── iport/          # Entry point and CLI orchestration
├── internal/
│   ├── netutil/        # Low-level network primitives
│   ├── scanner/        # Core scanning logic and protocol probes
│   ├── ui/             # UI formatting and display logic
│   └── webcheck/       # Website diagnostic tools
└── go.mod              # Module definition
```

## Directory Purposes

**cmd/:**
- Purpose: Contains application entry points.
- Key files: `cmd/iport/main.go`

**internal/:**
- Purpose: Contains private package code that is only importable within this module.
- Key files: `internal/scanner/probes.go`, `internal/ui/print.go`

## Key File Locations

**Entry Points:**
- `cmd/iport/main.go`: Main execution flow for the CLI.

**Core Logic:**
- `internal/scanner/`: Handles connectivity checks (`probe_transport.go`), protocol-specific probing (`probe_*.go`), and proxy detection (`proxy.go`).

**Testing:**
- `internal/netutil/host_test.go`
- `internal/webcheck/webcheck_test.go`

## Naming Conventions

**Files:**
- snake_case: `probe_advanced.go`, `print.go`

**Directories:**
- snake_case: `netutil`, `webcheck`

## Where to Add New Code

**New Probe Protocol:**
- Implementation: Add a new `probe_*.go` file in `internal/scanner/`.

**New UI component:**
- Implementation: Add logic in `internal/ui/print.go`.

---

*Structure analysis: 2026-04-22*
