# Contributing to iport

Thank you for your interest in improving `iport`! This guide covers how to add new protocol probes, follow code conventions, and ensure your changes are tested.

## Table of Contents

- [Getting Started](#getting-started)
- [Adding a New Protocol Probe](#adding-a-new-protocol-probe)
- [Code Conventions](#code-conventions)
- [Testing Requirements](#testing-requirements)
- [Submitting Changes](#submitting-changes)

---

## Getting Started

### Prerequisites

- Go 1.25.0 or later
- Basic understanding of the target proxy protocol's wire format
- Familiarity with Go concurrency patterns (goroutines, channels, `sync`)

### Build & Test

```bash
# Build
go build ./cmd/iport

# Run tests
go test ./...

# Run with verbose output
go test -v ./...

# Check coverage
go test -cover ./...
```

---

## Adding a New Protocol Probe

### Step 1: Choose the Right File

Probes are organized by complexity and transport. Add your probe to the appropriate file:

| File | Probe Type | Examples |
|------|-----------|----------|
| `probe_easy.go` | Deterministic handshakes | SOCKS5, HTTP Proxy, SSH |
| `probe_medium.go` | Payload/entropy analysis | Shadowsocks, VMess (raw) |
| `probe_tls.go` | TLS-encapsulated protocols | Trojan, VLESS, VMess/TLS |
| `probe_advanced.go` | TLS fingerprinting / camouflage | Reality, ShadowTLS, NaiveProxy |
| `probe_transport.go` | HTTP upgrade protocols | WebSocket, gRPC, HTTPUpgrade |
| `probe_udp.go` | UDP/QUIC-based protocols | WireGuard, Hysteria2, TUIC |
| `probe_misc.go` | Specialized / one-off | Snell, obfs4, Brook |

If your protocol doesn't fit existing categories, create a new `probe_<category>.go` file.

### Step 2: Implement the Probe Function

A probe function has this signature:

```go
func probeMyProtocol(host, port string, timeout time.Duration) []ProbeResult
```

**Template:**

```go
package scanner

import (
	"time"
)

func init() {
	// Register your probe in the appropriate registry
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"MyProtocol", probeMyProtocol},
	)
	// Use AllUDPProbes for UDP-based protocols
}

// probeMyProtocol detects MyProtocol proxy servers.
// Detection strategy: [brief description of approach]
func probeMyProtocol(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// 1. Send protocol-specific handshake / payload
	// 2. Read and analyze response
	// 3. Return ProbeResult with confidence based on specificity

	// Example: deterministic handshake
	if _, err := conn.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		return nil
	}

	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}

	if buf[0] == 0x01 && buf[1] == 0x02 {
		return []ProbeResult{{
			Protocol:   "MyProtocol",
			Transport:  "TCP",
			Confidence: 90, // High: deterministic response
		}}
	}

	return nil
}
```

**Key Rules:**

1. **Always use `dialTCP` / `dialUDP` / `dialTLSRaw`** — Don't use `net.Dial` directly; these helpers handle DNS pin-once and global semaphore.
2. **Always set deadlines** — `conn.SetDeadline(time.Now().Add(timeout))`
3. **Return `nil` on inconclusive** — Don't return low-confidence guesses; let the caller decide.
4. **Use `ProbeResult` correctly:**
   - `Protocol`: Human-readable name (e.g., `VLESS`, `Trojan`)
   - `Transport`: Lower-layer transport (`TCP`, `TLS`, `WebSocket`, `QUIC`)
   - `Confidence`: 0-100, calibrated to response specificity

### Step 3: Confidence Calibration Guide

Use these guidelines when assigning confidence scores:

| Confidence | When to Use |
|-----------|-------------|
| 90-100% | Deterministic handshake with unique response (SOCKS5, WireGuard) |
| 70-89% | Strong behavioral signal with minimal ambiguity (WebSocket upgrade, gRPC) |
| 50-69% | Differential analysis with some overlap (Trojan, VLESS via TLS behavior) |
| 40-49% | Weak signal; only report if no stronger signal exists |
| < 40% | Don't report — too likely to be noise |

### Step 4: Add Tests

Create a table-driven test in the same package:

```go
// probe_myprotocol_test.go
package scanner

import (
	"testing"
	"time"
)

func TestProbeMyProtocol(t *testing.T) {
	// Test against a known server, or use a mock
	// For unit tests, prefer mocking network responses

	results := probeMyProtocol("127.0.0.1", "1080", 2*time.Second)
	if len(results) == 0 {
		t.Fatal("expected detection against known MyProtocol server")
	}

	found := false
	for _, r := range results {
		if r.Protocol == "MyProtocol" && r.Confidence >= 70 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected high-confidence MyProtocol detection, got %+v", results)
	}
}
```

**Testing Tips:**

- Use `httptest` or custom `net.Listener` mocks for HTTP-based protocols
- For TLS protocols, generate test certificates with `crypto/tls` helpers
- Test edge cases: timeout, partial response, wrong protocol response

### Step 5: Update Documentation

After adding a probe:

1. Add it to the protocol table in `README.md`
2. Add detection details to `PROBING.md`
3. Update `README.md` probe count (e.g., "25 proxy/tunnel protocols")

---

## Code Conventions

### File Naming

- Use `snake_case`: `probe_myprotocol.go`, `probe_myprotocol_test.go`

### Function Naming

- Probe functions: `probe<ProtocolName>` (e.g., `probeSOCKS5`, `probeTrojan`)
- Helper functions: `camelCase`, unexported

### Imports

Group in this order:

```go
import (
	// 1. Standard library
	"crypto/tls"
	"fmt"
	"time"

	// 2. Third-party (if any)
	"github.com/some/lib"

	// 3. Internal packages
	"github.com/txdywy/iport/internal/netutil"
)
```

### Error Handling

Follow standard Go idioms:

```go
conn, err := dialTCP(host, port, timeout)
if err != nil {
	return nil  // Probes return nil on failure
}
defer conn.Close()
```

### Comments

- Exported functions: doc comment explaining purpose and detection strategy
- Complex logic: inline comments explaining the "why"

Example:

```go
// probeTrojan detects Trojan protocol over TLS.
// Trojan servers read 56 hex chars + \r\n before deciding to proxy or fallback.
// We compare behavior across short payload, fake auth, and HTTP GET.
func probeTrojan(host, port string, timeout time.Duration) []ProbeResult {
```

---

## Testing Requirements

All new probes must include:

1. **Unit tests** for payload construction and response parsing (mock-based)
2. **Integration tests** against a real server if possible (tagged with `//go:build integration`)
3. **Edge case coverage**: timeout, malformed response, empty response

Run the full test suite before submitting:

```bash
go test ./...
go test -race ./...  # Detect data races
```

---

## Submitting Changes

1. **Fork and branch** from `main`
2. **Write tests** that pass
3. **Update documentation** (README, PROBING.md)
4. **Verify** with `go test ./...` and `go build ./cmd/iport`
5. **Commit** with a clear message:
   - `feat: add XXX protocol probe`
   - `docs: update PROBING.md with XXX detection details`

---

*Last updated: 2026-04-23*
