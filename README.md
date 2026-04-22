# iport

A fast, zero-configuration network probe and diagnostic tool.

Point `iport` at any target and it concurrently checks L3/L4 connectivity, TLS protocol support, L7 application protocols (HTTP/2, HTTP/3), and actively probes for **25 proxy/tunnel protocols** with confidence scoring. No flags required for a useful report.

## Features

- **L3/L4 Connectivity** -- Concurrent ICMP ping (IPv4/IPv6) and TCP/UDP port scanning with configurable concurrency.
- **TLS Version Scanning** -- Checks TLS 1.0, 1.1, 1.2, and 1.3 support, reporting negotiated cipher suites.
- **HTTP Protocol Detection** -- Negotiates HTTP/1.1 and HTTP/2 via ALPN; checks HTTP/3 (QUIC) over UDP.
- **Proxy Protocol Detection** -- Actively probes open ports for 25 proxy/tunnel protocols with confidence scoring and transport layer identification.
- **Website Connectivity Diagnosis** -- `-G` performs layered checks (DNS, TCP, TLS/SNI, HTTP, QUIC) to identify the root cause of access failures, including GFW-style blocking signals.
- **DNS Pin-Once Architecture** -- Resolves DNS once and pins the IP for all subsequent operations, ensuring consistent results.
- **Static Binary** -- Single Go binary with no external dependencies.

## Installation

```bash
go install github.com/txdywy/iport/cmd/iport@latest
```

## Usage

```bash
# Basic scan (defaults to ports 80, 443 over TCP+UDP)
iport example.com

# Specify custom ports
iport 192.168.1.100 -p 80,443,8080,8443

# Scan all 65535 ports (proxy detection auto-disabled for performance)
iport example.com -A

# TCP only
iport example.com -T

# UDP only
iport example.com -U

# Proxy detection only (skip TLS/HTTP analysis)
iport 192.168.1.100 -p 443,1080,8388 -probe-only

# Disable proxy detection
iport example.com -probe=false

# Diagnose website accessibility and likely blocking root cause
iport -G https://example.com

# List all supported proxy protocol probes
iport -list-probes

# Adjust timeout (milliseconds) and concurrency
iport example.com -A -timeout 5000 -c 2000
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | | Target IP or domain (also accepted as positional argument) |
| `-p` | `80,443` | Ports to scan (comma separated, 1-65535) |
| `-A` | `false` | Scan all 65535 ports |
| `-T` | `false` | TCP only |
| `-U` | `false` | UDP only |
| `-c` | `1000` | Maximum concurrent scans |
| `-timeout` | `2000` | Timeout in milliseconds |
| `-probe` | `true` | Enable proxy protocol detection |
| `-probe-only` | `false` | Skip TLS/HTTP analysis, only run proxy probes |
| `-list-probes` | `false` | List all 25 supported protocol probes and exit |
| `-G` | | Diagnose website accessibility |
| `-V` | `false` | Show version and exit |

## Supported Proxy Protocols

25 protocol probes organized by detection complexity:

| Category | Protocols | Detection Method |
|----------|-----------|-----------------|
| Classic Proxy | SOCKS5, HTTP Proxy, SSH Tunnel | Standard handshake |
| Shadowsocks | Shadowsocks (AEAD), SS over TLS | Salt/payload analysis, entropy |
| V2Ray/Xray | VMess, VMess/TLS, VLESS, VLESS+Reality, VLESS+XTLS-Vision | Protocol header probing, TLS fingerprint mismatch |
| Trojan | Trojan over TLS | SHA224 auth probe, fallback detection |
| Modern (UDP) | Hysteria2, TUIC | QUIC ALPN fingerprinting |
| WireGuard | WireGuard | Handshake initiation/response |
| TLS Disguise | ShadowTLS v3, AnyTLS, NaiveProxy | TLS session analysis, H2 CONNECT probe |
| Transport | WebSocket, gRPC, HTTPUpgrade, XHTTP | HTTP upgrade, H2 frame probing |
| Other | Snell, obfs4 (Tor), Brook, mKCP | Protocol-specific probes |

Confidence levels: High (>=80%) / Medium (40-79%) / Low (<40%)

## Website Diagnosis (`-G`)

The `-G` flag runs a multi-layer diagnostic to identify why a website may be unreachable:

1. **DNS** -- Queries system resolver, public DNS (1.1.1.1, 8.8.8.8, 223.5.5.5), and DoH endpoints; compares results to detect poisoning.
2. **TCP** -- Tests TCP connectivity to resolved IPs with multiple attempts.
3. **TLS/SNI** -- Compares TLS handshakes with the real SNI, no SNI, and a wrong SNI to detect SNI-based filtering.
4. **HTTP** -- Sends HTTP requests with normal and control Host headers to detect Host-based filtering.
5. **HTTP/3 QUIC** -- Tests QUIC connectivity with target and control SNI to detect QUIC-level blocking.

Verdicts: `Normal` / `Abnormal` / `Likely GFW Interference` / `Inconclusive`

## Example Output

```
Target: 192.168.1.100

[L3/L4 Basic Connectivity]
  ICMP Ping: RTT: 2.1ms
  TCP Port 443: Open
  TCP Port 1080: Open

[TLS Detection (Port 443)]
  TLS 1.2: Supported (Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
  TLS 1.3: Supported (Cipher: TLS_AES_128_GCM_SHA256)

[Application Layer (L7) (Port 443)]
  HTTP (over TCP): Negotiated: h2 (Status: 200)

[Proxy Protocol Detection (TCP Port 443)]
  Trojan over TLS 65%
  VLESS over TLS 50%

[Proxy Protocol Detection (TCP Port 1080)]
  SOCKS5 over TCP 95%

=== Proxy Protocol Summary ===
  Port 1080   SOCKS5 over TCP                      95%
  Port 443    Trojan over TLS                       65%
  Port 443    VLESS over TLS                        50%
```

## Architecture

```
cmd/iport/main.go          CLI entry point, flag parsing, scan orchestration
internal/scanner/
  probes.go                 Core scanning (TCP, UDP, TLS, HTTP, HTTP/3, ICMP)
  proxy.go                  Probe runner with bounded concurrency
  probe_easy.go             SOCKS5, HTTP Proxy, SSH
  probe_medium.go           Shadowsocks, VMess
  probe_tls.go              Trojan, VLESS, VMess/TLS, SS/TLS
  probe_advanced.go         Reality, XTLS-Vision, ShadowTLS, AnyTLS, NaiveProxy
  probe_transport.go        WebSocket, gRPC, HTTPUpgrade, XHTTP
  probe_udp.go              WireGuard, Hysteria2, TUIC, mKCP
  probe_misc.go             Snell, obfs4, Brook
  host.go                   DNS pin-once, host normalization
internal/ui/print.go        Terminal output formatting
internal/netutil/host.go    Shared host/URL utilities
internal/webcheck/          Website connectivity diagnosis engine
```
