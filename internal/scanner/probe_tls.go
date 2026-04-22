package scanner

import (
	"crypto/rand"
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

	// Trojan auth threshold: server reads 56 hex chars + \r\n = 58 bytes before deciding.
	// Detection: compare response behavior for <58B vs >=58B vs HTTP GET.
	// Trojan with fallback: all three get HTTP response, but <58B may have different latency.
	// Trojan without fallback: <58B may timeout (server waiting), >=58B closes immediately.

	type probeOut struct {
		hasHTTP   bool
		noData    bool
		latencyMs int64
	}

	doTLSProbe := func(payload []byte) probeOut {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			return probeOut{noData: true}
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		if _, err := conn.Write(payload); err != nil {
			return probeOut{noData: true}
		}
		start := time.Now()
		resp, _ := readWithTimeout(conn, shortTimeout)
		ms := time.Since(start).Milliseconds()
		return probeOut{
			hasHTTP:   len(resp) > 0 && strings.Contains(string(resp), "HTTP/"),
			noData:    len(resp) == 0,
			latencyMs: ms,
		}
	}

	// Run 3 probes concurrently
	ch1 := make(chan probeOut, 1) // short: 30 bytes (< 58 threshold)
	ch2 := make(chan probeOut, 1) // long: fake Trojan auth (>= 58 bytes)
	ch3 := make(chan probeOut, 1) // HTTP GET

	go func() {
		p := make([]byte, 30)
		rand.Read(p)
		ch1 <- doTLSProbe(p)
	}()
	go func() {
		var fakeHash [28]byte
		rand.Read(fakeHash[:])
		trojanReq := fmt.Sprintf("%s\r\n\x01\x03\x0bexample.com\x00\x50\r\n", hex.EncodeToString(fakeHash[:]))
		ch2 <- doTLSProbe([]byte(trojanReq))
	}()
	go func() {
		ch3 <- doTLSProbe([]byte("GET / HTTP/1.1\r\nHost: " + HostForHTTP(host) + "\r\n\r\n"))
	}()

	short, long, http := <-ch1, <-ch2, <-ch3

	// Case 1: HTTP probe gets HTTP, Trojan-auth probe gets HTTP (fallback), short probe gets HTTP
	// → Trojan with fallback. Detect via latency difference: short probe may be slower
	// (server waits for more bytes before fallback) vs long probe (immediate fallback).
	if long.hasHTTP && http.hasHTTP {
		confidence := 65.0
		// Latency difference: if short probe is notably slower, server was buffering
		if short.latencyMs > long.latencyMs+50 {
			confidence = 75 // server waited for more data on short probe
		}
		if !short.hasHTTP && long.hasHTTP {
			confidence = 80 // short probe didn't even get HTTP → server buffered past timeout
		}
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: confidence}}
	}

	// Case 2: HTTP works but Trojan-auth doesn't → strong signal (no fallback configured)
	if !long.hasHTTP && http.hasHTTP {
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 75}}
	}

	// Case 3: Nothing works for any probe → not enough evidence
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

	// VLESS auth threshold: server reads 1B version + 16B UUID = 17 bytes before deciding.
	// Detection: send proper VLESS header with random UUID, check for 0x00 0x00 response
	// or compare <17B vs >=17B behavior.

	type probeOut struct {
		resp      []byte
		latencyMs int64
	}

	doTLSProbe := func(payload []byte) probeOut {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			return probeOut{}
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		if _, err := conn.Write(payload); err != nil {
			return probeOut{}
		}
		start := time.Now()
		resp, _ := readWithTimeout(conn, shortTimeout)
		return probeOut{resp: resp, latencyMs: time.Since(start).Milliseconds()}
	}

	// Probe 1: Valid VLESS header with random UUID
	vlessHeader := make([]byte, 0, 64)
	vlessHeader = append(vlessHeader, 0x00) // version
	uuid := make([]byte, 16)
	rand.Read(uuid)
	vlessHeader = append(vlessHeader, uuid...)
	vlessHeader = append(vlessHeader, 0x00)       // addons length = 0
	vlessHeader = append(vlessHeader, 0x01)       // cmd: TCP
	vlessHeader = append(vlessHeader, 0x00, 0x50) // port 80
	vlessHeader = append(vlessHeader, 0x02, 0x0b) // domain, len 11
	vlessHeader = append(vlessHeader, []byte("example.com")...)

	// Probe 2: Short payload (< 17 bytes)
	shortPayload := make([]byte, 10)
	rand.Read(shortPayload)

	ch1 := make(chan probeOut, 1)
	ch2 := make(chan probeOut, 1)
	go func() { ch1 <- doTLSProbe(vlessHeader) }()
	go func() { ch2 <- doTLSProbe(shortPayload) }()

	vless, short := <-ch1, <-ch2

	// Check for VLESS response header: 0x00 0x00 (version=0, addon_len=0)
	if len(vless.resp) >= 2 && vless.resp[0] == 0x00 && vless.resp[1] == 0x00 {
		return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 90}}
	}

	// Check for VLESS response with addons: 0x00 + non-zero addon length
	if len(vless.resp) >= 2 && vless.resp[0] == 0x00 && vless.resp[1] > 0 {
		return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: 85}}
	}

	// Fallback detection: VLESS header got HTTP (fallback), short probe behavior differs
	vlessHTTP := len(vless.resp) > 0 && strings.Contains(string(vless.resp), "HTTP/")
	shortHTTP := len(short.resp) > 0 && strings.Contains(string(short.resp), "HTTP/")

	if vlessHTTP {
		confidence := 55.0
		// Short probe slower (server buffering <17B) vs VLESS probe (immediate fallback)
		if short.latencyMs > vless.latencyMs+50 {
			confidence = 70
		}
		if !shortHTTP {
			confidence = 75 // short probe didn't get HTTP → server waited for more bytes
		}
		return []ProbeResult{{Protocol: "VLESS", Transport: "TLS", Confidence: confidence}}
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
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	resp, err := readWithTimeout(conn, shortTimeout)

	if len(resp) == 0 && err != nil {
		// Timeout/close only — too ambiguous, don't report
		return nil
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
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	resp, err := readWithTimeout(conn, shortTimeout)
	if len(resp) == 0 && err != nil {
		// Timeout/close only — too ambiguous, don't report
		return nil
	}
	if len(resp) > 0 && ShannonEntropy(resp) > 7.5 {
		return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TLS", Confidence: 40}}
	}
	return nil
}
