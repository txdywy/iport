# Troubleshooting Guide

Common issues when using `iport` and how to resolve them.

## Table of Contents

- [No Results / All Ports Filtered](#no-results--all-ports-filtered)
- [Slow Scans](#slow-scans)
- [False Positives](#false-positives)
- [False Negatives](#false-negatives)
- [UDP Scan Issues](#udp-scan-issues)
- [Website Diagnosis (`-G`) Issues](#website-diagnosis--g-issues)
- [Build / Runtime Errors](#build--runtime-errors)

---

## No Results / All Ports Filtered

### Symptom

```
Target: example.com
[L3/L4 Basic Connectivity]
  ICMP Ping: timeout
  TCP Port 80: Closed/Filtered
  TCP Port 443: Closed/Filtered
```

### Causes & Solutions

| Cause | Diagnosis | Solution |
|-------|-----------|----------|
| **Target is down** | Ping fails consistently | Verify target with `ping` or `curl` |
| **Firewall blocks scanner IP** | Works from another network | Use `-G` to diagnose blocking; try different source IP |
| **Rate limiting** | First few ports open, then all filtered | Reduce concurrency: `-c 100` |
| **Wrong target format** | IP resolution fails | Use IP directly or verify DNS: `dig example.com` |
| **IPv6 / IPv4 mismatch** | Target has both, one path is down | Force IPv4: use IP literal; check both stacks |

### Quick Checks

```bash
# Verify basic connectivity
ping -c 3 example.com
curl -I http://example.com

# Check if specific port is reachable
nc -vz example.com 443

# Try with lower concurrency
iport example.com -c 100 -timeout 5000
```

---

## Slow Scans

### Symptom

Scan takes much longer than expected even with high concurrency.

### Causes & Solutions

| Cause | Fix |
|-------|-----|
| **DNS resolution slow** | Use IP address directly; check local resolver |
| **High `-c` value causing throttling** | Reduce to `-c 500` or `-c 200` |
| **Proxy probes on many ports** | Use `-probe=false` for pure port scan; or `-probe-only` on specific ports |
| **All-port scan (`-A`)** | Expected: 65535 ports takes time even at high concurrency |
| **UDP timeouts** | UDP scans are inherently slower; use `-T` for TCP-only |

### Performance Tuning

```bash
# Fast TCP-only port scan (no proxy detection)
iport example.com -p 80,443,8080,8443 -T -probe=false -c 2000 -timeout 1000

# Fast UDP scan
iport example.com -p 53,123,443 -U -probe=false -c 500

# Full scan with reasonable settings
iport example.com -A -c 1000 -timeout 2000
```

### Expected Timing

| Scan Type | Ports | Typical Time | Settings |
|-----------|-------|-------------|----------|
| Quick | 2 | 2-5s | defaults |
| Common web | 4 | 3-6s | defaults |
| Top 1000 | 1000 | 15-30s | `-c 2000` |
| All ports | 65535 | 2-5min | `-A -c 2000 -timeout 1500` |

---

## False Positives

### Symptom

Reported proxy protocols that don't actually exist on the target.

### Common Cases

| False Positive | Why It Happens | How to Verify |
|----------------|---------------|---------------|
| **HTTP Proxy on port 443** | CDN or server accepts `CONNECT` | Run `curl -x http://target:443 http://example.com` |
| **Shadowsocks on closed port** | Silent drop looks like SS | Check if port is actually open with TCP connect |
| **VLESS/Trojan on any TLS port** | TLS close behavior is ambiguous | Check if real proxy credentials work |
| **Multiple protocols on same port** | Aggregation boosts weak signals | Look at individual confidence scores |

### Reducing False Positives

1. **Check confidence levels**: Only trust High (>= 80%) for definitive conclusions
2. **Use `-probe-only`**: Eliminates TLS/HTTP overlap that can confuse detection
3. **Cross-reference**: Compare scan results from different network positions
4. **Manual verification**: Use actual client software to confirm protocol presence

---

## False Negatives

### Symptom

Known proxy server not detected.

### Common Cases

| False Negative | Why It Happens | Solution |
|----------------|---------------|----------|
| **Protocol uses non-standard port** | Probes still run, but timeout budget may be tight | Increase `-timeout` |
| **Protocol behind CDN/WAF** | WAF modifies or drops probe payloads | Scan direct IP, not CDN domain |
| **Rate limiting triggers** | Server drops connections after N probes | Reduce `-c`, increase `-timeout` |
| **VMess with custom UUID/alterId** | Handshake requires valid credentials | Cannot detect; protocol is designed to be stealthy |
| **Shadowsocks with non-AEAD cipher** | Only AEAD ciphers are probed | No current workaround |
| **Protocol uses custom transport** | e.g., VMess over WebSocket with path | May not match standard probe patterns |

---

## UDP Scan Issues

### Symptom

UDP scan shows all ports "open" or takes extremely long.

### Explanation

UDP scanning is inherently unreliable because:
- **No handshake**: Unlike TCP, UDP has no connection setup
- **No response = ambiguous**: Is the port open (silently accepting) or filtered (dropped)?
- **ICMP rate limiting**: Some OSes limit ICMP "port unreachable" responses

### Solutions

```bash
# UDP scan with longer timeout (UDP needs more time)
iport example.com -U -timeout 5000 -c 500

# UDP + proxy probes (for Hysteria2, TUIC, WireGuard, mKCP)
iport example.com -p 443,51820 -U

# Skip UDP if not needed
iport example.com -T  # TCP only
```

---

## Website Diagnosis (`-G`) Issues

### Symptom

`-G` flag produces "Inconclusive" or unexpected verdicts.

### Understanding Verdicts

| Verdict | Meaning | Next Steps |
|---------|---------|-----------|
| **Normal** | All layers pass; website is accessible | If you still can't access, check local network/DNS |
| **Abnormal** | Some layers fail, but not GFW-pattern | Check target server health, certificate validity |
| **Likely GFW Interference** | Multiple GFW indicators detected | Try different access method (VPN, proxy, DoH) |
| **Inconclusive** | Conflicting or insufficient evidence | Run again; try from different network location |

### Specific `-G` Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| **All DNS resolvers timeout** | Local DNS blocked or broken | Check `/etc/resolv.conf`; try `dig @1.1.1.1 example.com` |
| **TCP works but TLS fails** | SNI-based blocking or certificate issue | `-G` will flag this; compare with/without SNI |
| **TLS works but HTTP fails** | Host-header blocking or server error | Check with `curl -H "Host: ..."` |
| **QUIC fails but TCP works** | UDP/QUIC specifically blocked | Common GFW behavior; use TCP-based access |

### Diagnosing Your Own Network

```bash
# Test DNS resolution specifically
iport -G https://example.com
# Look at "DNS" layer: do multiple resolvers agree?

# Compare with a control domain known to work
iport -G https://cloudflare.com
```

---

## Build / Runtime Errors

### `go build` fails

```bash
# Ensure Go 1.25+
go version

# Download dependencies
go mod tidy
go mod download

# Build
go build ./cmd/iport
```

### QUIC / HTTP/3 compilation issues

The `quic-go` dependency requires CGO on some platforms:

```bash
# If CGO is unavailable, try:
CGO_ENABLED=0 go build ./cmd/iport

# Or update to latest quic-go:
go get github.com/quic-go/quic-go@latest
```

### Permission denied (ICMP ping)

ICMP requires raw socket privileges on most systems:

```bash
# Linux: run with cap_net_raw
sudo setcap cap_net_raw=+ep ./iport

# Or run with sudo (not recommended for regular use)
sudo ./iport example.com

# macOS: may prompt for permission on first run
```

### "too many open files"

Reduce concurrency to stay within file descriptor limits:

```bash
# Check limit
ulimit -n

# Reduce concurrency
iport example.com -A -c 500
```

---

*Last updated: 2026-04-23*
