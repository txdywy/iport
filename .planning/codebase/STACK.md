# Technology Stack

**Analysis Date:** 2026-04-22

## Languages

**Primary:**
- Go 1.25.0 - Used for CLI tool development, networking, and concurrency.

## Runtime

**Environment:**
- Compiled binary (Go)

**Package Manager:**
- Go Modules
- Lockfile: `go.sum` (present)

## Frameworks

**Core:**
- `github.com/quic-go/quic-go` v0.59.0 - Implementation of QUIC and HTTP/3.
- `golang.org/x/net` v0.53.0 - Low-level networking utilities.
- `github.com/fatih/color` v1.19.0 - Terminal output styling.

**Testing:**
- Standard library `testing` (inferred)

**Build/Dev:**
- Go Toolchain (Standard)

## Key Dependencies

**Critical:**
- `github.com/quic-go/quic-go` - Required for HTTP/3 diagnostics.
- `golang.org/x/net` - Required for network stack operations (ping, TCP/UDP scanning).

## Configuration

**Environment:**
- Standard Go `flag` package used for CLI options. No external configuration files required.

**Build:**
- None detected.

## Platform Requirements

**Development:**
- Go 1.25.0+ installed on the host.

**Production:**
- Compiled statically-linked binary (platform-dependent).

---

*Stack analysis: 2026-04-22*
