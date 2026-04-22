package scanner

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"Trojan", probeTrojan},
		NamedProbe{"VLESS", probeVLESS},
		NamedProbe{"VMess/TLS", probeVMessTLS},
		NamedProbe{"SS/TLS", probeSSTLS},
	)
}

// probeTrojan detects Trojan protocol over TLS.
// Trojan: TLS → SHA224(password) + \r\n + SOCKS5-addr + \r\n + payload
// Invalid password → server forwards to fallback (HTTP response) or closes.
// We compare behavior: Trojan-specific payload vs plain HTTP request.
func probeTrojan(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// Probe 1: Send Trojan-style auth (fake SHA224 hash)
	conn1, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn1.Close()

	// Trojan expects: hex(SHA224(password)) + \r\n + cmd(1) + atype(1) + addr + port + \r\n
	fakeHash := sha256.Sum224([]byte("iport-probe-fake-password"))
	trojanReq := fmt.Sprintf("%s\r\n\x01\x03\x0bexample.com\x00\x50\r\n", hex.EncodeToString(fakeHash[:]))
	conn1.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn1.Write([]byte(trojanReq))

	resp1, err1 := readWithTimeout(conn1, shortTimeout)

	// Probe 2: Send plain HTTP GET for comparison
	conn2, err2 := dialTLSRaw(host, port, timeout)
	if err2 != nil {
		// Can't do comparison — use single probe result
		if err1 != nil && len(resp1) == 0 {
			return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 45}}
		}
		if len(resp1) > 0 && strings.Contains(string(resp1), "HTTP/") {
			// Got HTTP fallback response — strong Trojan signal
			return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 70}}
		}
		return nil
	}
	defer conn2.Close()

	conn2.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn2.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"))
	resp2, _ := readWithTimeout(conn2, shortTimeout)

	// Analysis: Trojan with fallback returns HTTP for both, but with different timing/content
	// Trojan without fallback: closes on invalid auth, but serves HTTP on plain request
	hasHTTP1 := len(resp1) > 0 && strings.Contains(string(resp1), "HTTP/")
	hasHTTP2 := len(resp2) > 0 && strings.Contains(string(resp2), "HTTP/")

	if hasHTTP1 && hasHTTP2 {
		// Both return HTTP — Trojan with fallback web server
		// Trojan's fallback response may differ from direct HTTP (different server header, timing)
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 65}}
	}
	if !hasHTTP1 && hasHTTP2 {
		// Trojan-style payload caused close/error, but HTTP works — strong Trojan signal
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 75}}
	}
	if !hasHTTP1 && !hasHTTP2 {
		// Neither works — could be Trojan without fallback, or non-HTTP TLS service
		if err1 != nil {
			return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 40}}
		}
	}
	return nil
}

// probeVLESS detects VLESS protocol over TLS.
// VLESS header: version(1) + UUID(16) + addons_len(1) + addons + cmd(1) + addr
// Invalid UUID → server closes connection (no fallback in most configs).
func probeVLESS(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	conn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// VLESS request: version=0, random UUID, no addons, cmd=1(TCP), addr=example.com:80
	header := make([]byte, 0, 64)
	header = append(header, 0x00) // version
	uuid := make([]byte, 16)
	rand.Read(uuid)
	header = append(header, uuid...)
	header = append(header, 0x00)                         // addons length = 0
	header = append(header, 0x01)                         // cmd: TCP
	header = append(header, 0x00, 0x50)                   // port 80
	header = append(header, 0x02)                         // addr type: domain
	header = append(header, 0x0b)                         // domain length: 11
	header = append(header, []byte("example.com")...)

	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn.Write(header)

	start := time.Now()
	resp, err := readWithTimeout(conn, shortTimeout)
	elapsed := time.Since(start)

	if len(resp) == 0 && err != nil {
		// Connection closed with no data — consistent with VLESS invalid UUID
		if elapsed < shortTimeout/2 {
			return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 60}}
		}
		return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 45}}
	}

	if len(resp) > 0 {
		// VLESS response header: version(1) + addons_len(1) + addons
		if resp[0] == 0x00 && len(resp) >= 2 {
			return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 85}}
		}
		// Got HTTP response — might be VLESS with fallback
		if strings.Contains(string(resp), "HTTP/") {
			return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 50}}
		}
	}
	return nil
}

// probeVMessTLS detects VMess over TLS.
func probeVMessTLS(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	conn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// VMess auth: 16-byte HMAC(timestamp, UUID) + encrypted request
	payload := make([]byte, 56)
	rand.Read(payload)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn.Write(payload)

	start := time.Now()
	resp, err := readWithTimeout(conn, shortTimeout)
	elapsed := time.Since(start)

	if len(resp) == 0 && err != nil && elapsed < shortTimeout/2 {
		return []ProbeResult{{Protocol: "VMess", Transport: "TLS", Confidence: 50}}
	}
	if len(resp) > 0 && ShannonEntropy(resp) > 7.5 {
		return []ProbeResult{{Protocol: "VMess", Transport: "TLS", Confidence: 45}}
	}
	return nil
}

// probeSSTLS detects Shadowsocks over TLS.
func probeSSTLS(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	conn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// SS AEAD over TLS: 32-byte salt + encrypted payload
	payload := make([]byte, 50)
	rand.Read(payload)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn.Write(payload)

	resp, err := readWithTimeout(conn, shortTimeout)
	if len(resp) == 0 && err != nil {
		return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TLS", Confidence: 45}}
	}
	if len(resp) > 0 && ShannonEntropy(resp) > 7.5 {
		return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TLS", Confidence: 40}}
	}
	return nil
}
