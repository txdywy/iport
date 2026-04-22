# Proxy Protocol Detection Deep Dive

**iport** detects 25 proxy/tunnel protocols using active probing with confidence scoring. This document explains how detection works, why confidence levels vary, and how to interpret results.

## Table of Contents

- [Core Concepts](#core-concepts)
- [Confidence Scoring](#confidence-scoring)
- [Probe Categories](#probe-categories)
- [Protocol-Specific Detection Notes](#protocol-specific-detection-notes)
- [False Positives & Negatives](#false-positives--negatives)
- [Performance Characteristics](#performance-characteristics)

---

## Core Concepts

### Active Probing

Unlike passive fingerprinting (e.g., reading server banners), `iport` sends carefully crafted protocol handshakes and analyzes responses. This approach:

- **Confirms** protocol support rather than inferring it
- Works even when services hide banners or use TLS camouflage
- Can detect protocols layered inside other transports (e.g., VMess over TLS, Trojan over TLS)

### Transport Layer Separation

Each detection result includes both a **Protocol** (application-layer proxy type) and a **Transport** (how it's carried):

| Protocol | Possible Transports |
|----------|-------------------|
| SOCKS5 | TCP |
| HTTP Proxy | TCP |
| VMess | TCP, TLS, WebSocket, gRPC |
| VLESS | TCP, TLS, Reality, XTLS-Vision |
| Trojan | TLS |
| Shadowsocks | TCP, TLS |

This separation matters because the same proxy protocol can be deployed with or without TLS, and the detection strategy differs.

---

## Confidence Scoring

### How It Works

Each probe returns a confidence score (0-100) based on:

1. **Response specificity** — How uniquely the response matches the protocol specification
2. **Behavioral differential** — Comparing responses to different payloads to rule out false matches
3. **Protocol complexity** — Simple protocols (SOCKS5) have near-deterministic handshakes; complex ones (VMess) rely on behavioral analysis

### Score Interpretation

| Level | Range | Meaning |
|-------|-------|---------|
| **High** | >= 80% | Strong protocol indicators; response matches specification closely |
| **Medium** | 40-79% | Some indicators present; may overlap with other protocols or configurations |
| **Low** | < 40% | Weak signal; could be coincidence or a non-standard implementation |

### Multi-Probe Aggregation

When multiple probes detect the same `Protocol+Transport` combination, scores are merged using **probability union**:

```
merged = 100 * (1 - (1 - p1/100) * (1 - p2/100))
```

Example:
- Probe A detects VLESS/TLS at 40%
- Probe B detects VLESS/TLS at 35%
- Merged: `100 * (1 - 0.60 * 0.65) = 61%`

This captures the intuition that independent weak signals strengthen each other.

---

## Probe Categories

Probes are organized by detection complexity and are stored in separate source files:

### Easy (`probe_easy.go`) — Deterministic Handshakes

These protocols have well-defined, stateful handshakes. Detection is nearly binary.

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **SOCKS5** | Send greeting (`0x05 0x01 0x00`), expect version 5 + auth method | 95% |
| **HTTP Proxy** | Send `CONNECT`, expect HTTP response | 85% |
| **SSH Tunnel** | Read SSH banner (`SSH-2.0-...`) | 95% |

### Medium (`probe_medium.go`) — Payload Analysis

These require analyzing response entropy, timing, or payload structure.

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **Shadowsocks AEAD** | Send encrypted payload with random salt; analyze response timing/closure | 50-70% |
| **VMess (raw TCP)** | Send VMess handshake; check response structure | 60-75% |

### TLS-Cloaked (`probe_tls.go`) — Differential Analysis

Protocols hiding inside TLS connections require comparing behavior across multiple probe payloads.

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **Trojan** | Compare response to short payload (<58B), fake auth payload (>=58B), and HTTP GET | 55-70% |
| **VLESS** | Send VLESS handshake; analyze TLS close behavior vs. HTTP fallback | 50-65% |
| **VMess/TLS** | Send VMess-over-TLS handshake; compare to plain HTTPS response | 55-70% |
| **SS/TLS** | Shadowsocks handshake over TLS tunnel | 50-65% |

### Advanced (`probe_advanced.go`) — TLS Fingerprinting

These detect TLS-disguise protocols by analyzing TLS session behavior and ALPN negotiation.

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **VLESS+Reality** | Reality-specific TLS fingerprint mismatch; SNI spoofing behavior | 60-75% |
| **VLESS+XTLS-Vision** | Detect XTLS flow-control behavior post-handshake | 50-65% |
| **ShadowTLS v3** | TLS session analysis; compare handshake to expected shadow behavior | 55-70% |
| **AnyTLS** | Generic TLS tunnel detection via timing and payload analysis | 45-60% |
| **NaiveProxy** | H2 CONNECT probe with specific padding patterns | 60-75% |

### Transport (`probe_transport.go`) — HTTP Upgrade Detection

Detect protocols that upgrade from HTTP/1.1 or HTTP/2.

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **WebSocket** | Send upgrade request; parse WS frame in response | 80-90% |
| **gRPC** | H2 frame probing with gRPC-specific headers | 70-85% |
| **HTTPUpgrade** | Standard HTTP upgrade detection | 75-85% |
| **XHTTP** | XHTTP-specific upgrade pattern matching | 65-80% |

### UDP (`probe_udp.go`) — UDP/QUIC Probes

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **WireGuard** | Send handshake initiation; expect correct response type | 80-90% |
| **Hysteria2** | QUIC ALPN fingerprinting (`hysteria2`) | 75-85% |
| **TUIC** | QUIC ALPN and initial packet structure | 70-80% |
| **mKCP** | KCP-specific packet header analysis | 60-75% |

### Miscellaneous (`probe_misc.go`) — Specialized Protocols

| Protocol | Method | Typical Confidence |
|----------|--------|-------------------|
| **Snell** | Snell-specific handshake and cipher negotiation | 65-75% |
| **obfs4 (Tor)** | obfs4 bridge handshake with randomized padding | 50-65% |
| **Brook** | Brook protocol handshake analysis | 55-70% |

---

## Protocol-Specific Detection Notes

### Trojan

Trojan servers read exactly 56 hex characters + `\r\n` (58 bytes) before deciding whether to treat the connection as Trojan or forward to a fallback (typically a web server).

The probe sends three payloads concurrently:
1. **Short payload** (30 random bytes) — Server waits for more data or times out
2. **Fake auth payload** (valid-length but wrong hash) — Server closes immediately or returns fallback
3. **HTTP GET** — Falls through to web server

By comparing the three response patterns (presence of HTTP response, data vs. no data, latency), the probe distinguishes Trojan from plain HTTPS.

### VLESS + Reality

Reality is a TLS camouflage mechanism that forwards TLS handshakes to a real website ("dest") while intercepting VLESS traffic. Detection relies on:

1. **Certificate mismatch** — The returned certificate may not match the SNI being probed
2. **TLS fingerprint** — The server's supported ciphers/curves may differ from the claimed destination
3. **Behavioral differential** — Response to VLESS payload vs. standard HTTP request differs

### Shadowsocks AEAD

Shadowsocks has no server greeting — the server silently drops invalid requests. Detection is probabilistic:

1. Send a well-formed AEAD request with random key
2. If the server closes immediately (RST) vs. times out, this suggests Shadowsocks vs. open port
3. Timing analysis helps distinguish from other silent protocols

Because there's no positive confirmation, confidence is inherently capped around 70%.

### WireGuard

WireGuard uses a fixed message format for handshake initiation:
- Message type: `0x01`
- Sender index: random 32-bit value
- Ephemeral public key: 32 bytes (Curve25519)
- Encrypted static key: 32 bytes
- Encrypted timestamp: 12 bytes
- MAC1: 16 bytes

The probe sends a valid handshake initiation and checks if the response is a valid handshake response (message type `0x02`). This is deterministic, yielding high confidence.

---

## False Positives & Negatives

### Known Sources of False Positives

| Scenario | Cause | Mitigation |
|----------|-------|------------|
| HTTP Proxy on port 443 | Some CDNs accept `CONNECT` on any port | Check for 407 vs. 200; combine with TLS detection |
| Shadowsocks vs. random dropped port | Silent close looks the same | Multi-probe aggregation; timing heuristics |
| VLESS vs. plain TLS with early close | Some servers close on garbage data | Require multiple behavioral signals |

### Known Sources of False Negatives

| Scenario | Cause | Workaround |
|----------|-------|------------|
| Shadowsocks with non-AEAD cipher | Only AEAD ciphers are probed | Use `-probe-only` with specific ports |
| VMess with altered UUID | Handshake depends on valid UUID | No workaround; protocol inherently stealthy |
| Protocol behind CDN/WAF | WAF drops or modifies probe payloads | Try direct IP scan instead of domain |
| Rate limiting | Server throttles or bans after N probes | Increase `-timeout`; reduce `-c` |

---

## Performance Characteristics

### Per-Port Probe Budget

- **Single probe timeout**: Controlled by `-timeout` flag (default 2000ms)
- **Total per-port budget**: `3 * timeout` (e.g., 6000ms default)
- **Concurrent probes per port**: `maxProbeParallel = 4`
- **Global concurrency**: Controlled by `-c` flag (default 1000)

### Why Some Probes Are Slower

| Factor | Impact |
|--------|--------|
| TLS handshake | Adds 1-2 RTT plus certificate exchange |
| Differential probes (Trojan, VLESS) | Require 3+ sequential TLS connections |
| UDP/QUIC probes | Require UDP connectivity; may timeout if UDP is blocked |
| Timeout waiting | Protocols like Shadowsocks rely on timeout behavior |

### Disabling Probes for Speed

```bash
# Skip all proxy detection (fastest)
iport example.com -probe=false

# Only proxy detection, skip TLS/HTTP analysis
iport example.com -probe-only
```

---

*Last updated: 2026-04-23*
