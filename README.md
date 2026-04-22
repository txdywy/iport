# iport

A fast, zero-configuration, dependency-free network probe and diagnostic tool.

`iport` is designed to be the ultimate "Do What I Mean" network scanner. Instead of requiring you to remember complex flags like `nmap` or `curl`, you simply point `iport` at a target, and it concurrently checks L3/L4 connectivity, TLS protocol support, L7 application protocols (including HTTP/2 and HTTP/3), and **proxy/tunnel protocol detection** with confidence scoring.

## Features

- **L3/L4 Connectivity:** Concurrent ICMP Ping and TCP/UDP port checks.
- **TLS Version Scanning:** Automatically checks support for TLS 1.0, 1.1, 1.2, and 1.3, including cipher suites.
- **Advanced HTTP Protocols:** Negotiates HTTP/1.1 and HTTP/2 over ALPN, and checks for HTTP/3 (QUIC) support over UDP.
- **Proxy Protocol Detection:** Actively probes open ports to identify 25 proxy/tunnel protocols with confidence scoring and transport layer identification.
- **Zero Configuration:** Sane defaults give you a comprehensive report immediately.
- **Static Binary:** Built with Go, meaning it's a single binary with no external dependencies (no need for `nmap`, `openssl`, etc.).

## Supported Proxy Protocols

| Category | Protocols | Detection Method |
|----------|-----------|-----------------|
| Classic Proxy | SOCKS5, HTTP Proxy, SSH Tunnel | Standard handshake |
| Shadowsocks | Shadowsocks (AEAD), SS over TLS | Salt/payload analysis, entropy |
| V2Ray/Xray | VMess, VLESS, VLESS+Reality, VLESS+XTLS-Vision | Protocol header probing, TLS cert mismatch |
| Trojan | Trojan over TLS | SHA224 auth probe, fallback detection |
| Modern | Hysteria2, TUIC | QUIC ALPN fingerprinting |
| WireGuard | WireGuard | Handshake initiation/response |
| TLS Disguise | ShadowTLS v3, AnyTLS, NaïveProxy | TLS analysis, session behavior, H2 CONNECT |
| Transport | WebSocket, gRPC, HTTPUpgrade, XHTTP | HTTP upgrade, H2 probing |
| Other | Snell, obfs4 (Tor), Brook, mKCP | Protocol-specific probes |

Confidence levels: 🟢 High (≥80%) · 🟡 Medium (40-79%) · ⚪ Low (<40%)

## Installation

```bash
go install github.com/txdywy/iport/cmd/iport@latest
```

## Usage

```bash
# Basic usage (defaults to scanning ports 80 and 443 with proxy detection)
iport example.com

# Specify custom ports
iport 192.168.1.100 -p 80,443,8080,8443

# TCP only (skip UDP scanning and HTTP/3 check)
iport example.com -T

# Proxy detection only (skip TLS/HTTP analysis for speed)
iport 192.168.1.100 -p 443,1080,8388 -probe-only

# Disable proxy detection
iport example.com -probe=false

# List all supported proxy protocol probes
iport -list-probes

# Scan all 65535 TCP+UDP ports (proxy detection auto-disabled for performance)
iport example.com -A -U

# Scan all ports, TCP only
iport example.com -A

# Adjust timeout (in milliseconds)
iport example.com -timeout 5000

# Adjust concurrency
iport example.com -A -c 2000
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | | Target IP or domain |
| `-p` | `80,443` | Ports to scan (comma separated, validated 1-65535) |
| `-timeout` | `2000` | Timeout in milliseconds |
| `-A` | `false` | Scan all 65535 ports (TCP only; add -U for UDP) |
| `-T` | `false` | TCP only, skip UDP scanning and HTTP/3 |
| `-U` | `false` | Include UDP scanning (use with -A for full TCP+UDP) |
| `-c` | `1000` | Maximum concurrent scans |
| `-probe` | `true` | Enable proxy protocol detection |
| `-probe-only` | `false` | Skip TLS/HTTP, only run proxy probes |
| `-list-probes` | `false` | List all 25 supported protocol probes and exit |
| `-V` | `false` | Show version and exit |

## Example Output

```
🎯 Target: 192.168.1.100

[L3/L4 Basic Connectivity]
 🟢 ICMP Ping: RTT: 2.1ms
 🟢 TCP Port 443: Open
 🟢 TCP Port 1080: Open
─────────────────────────────────────────

[TLS Detection (Port 443)]
 🟢 TLS 1.2: Supported (Cipher: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
 🟢 TLS 1.3: Supported (Cipher: TLS_AES_128_GCM_SHA256)

[Application Layer (L7) (Port 443)]
 🟢 HTTP (over TCP): Negotiated: h2 (Status: 200)
─────────────────────────────────────────

[Proxy Protocol Detection (TCP Port 443)]
 🟡 Trojan over TLS 65%
 🟡 VLESS over TLS 50%

[Proxy Protocol Detection (TCP Port 1080)]
 🟢 SOCKS5 over TCP 95%

═══ Proxy Protocol Summary ═══
 🟢 Port 1080   SOCKS5 over TCP                      95%
 🟡 Port 443    Trojan over TLS                       65%
 🟡 Port 443    VLESS over TLS                        50%
```
