# Architecture

**Analysis Date:** 2026-04-22

## Pattern Overview

**Overall:** Concurrent pipeline-based network scanner.

**Key Characteristics:**
- Highly concurrent: Uses worker pools and goroutines to perform network probes across ports.
- Decoupled Result Reporting: Scanner components perform the work and emit `ScanResult` objects via a channel; a UI consumer renders these results.
- Modular Probing: Scanning logic is segmented by protocol and layer, residing in `internal/scanner`.

## Layers

**Scanner (Logic):**
- Purpose: Network connectivity, port scanning, protocol/proxy detection, and TLS/HTTP analysis.
- Location: `internal/scanner`
- Contains: Low-level network primitives (`netutil`), specific protocol probes (`probe_*.go`), and orchestration.
- Used by: `cmd/iport/main.go`

**UI (Presentation):**
- Purpose: Formatting and rendering results to the console.
- Location: `internal/ui`
- Contains: `print.go` which handles formatting strings and progress bars.
- Used by: `cmd/iport/main.go`

**WebCheck (Diagnostics):**
- Purpose: Website connectivity diagnostics.
- Location: `internal/webcheck`
- Used by: `cmd/iport/main.go`

## Data Flow

**Scanning:**

1. `main.go` initializes the target and concurrency settings.
2. `main.go` spawns worker goroutines for scanning (TCP/UDP).
3. Workers utilize `internal/scanner` functions to perform probes.
4. Workers push `ScanResult` objects to a `results` channel.
5. A central UI goroutine reads from the channel and calls `internal/ui` functions to output data to the user.

**State Management:**
- Concurrency control via a global semaphore in `scanner.SetSemaphore`.
- Synchronization via `sync.WaitGroup`, `sync.Mutex`, and `sync/atomic` in `main.go` to handle concurrent result collection from workers.

## Key Abstractions

**ScanResult:**
- Purpose: Unified object representing scanner output to decouple scanning from rendering.
- File: `cmd/iport/main.go`

## Entry Points

**Main Entry Point:**
- Location: `cmd/iport/main.go`
- Responsibilities: CLI flag parsing, initialization, orchestration of the scan pipeline, and teardown.

## Error Handling

**Strategy:** Error propagation from `scanner` to `main.go`.

**Patterns:**
- Errors are carried within the `ScanResult` object and passed to the UI renderer.
- Failures in non-critical scans (e.g., individual port probes) do not stop the entire process.

## Cross-Cutting Concerns

**Logging:** Uses `fmt` for standard output/errors in the `ui` package.
**Validation:** CLI arguments and port ranges are validated in `main.go`.

---

*Architecture analysis: 2026-04-22*
