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

	// Run both probes concurrently
	type probeOut struct {
		resp    []byte
		hasHTTP bool
	}
	ch1 := make(chan probeOut, 1)
	ch2 := make(chan probeOut, 1)

	// Probe 1: Trojan-style auth
	go func() {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			ch1 <- probeOut{}
			return
		}
		defer conn.Close()
		fakeHash := sha256.Sum224([]byte("iport-probe-fake-password"))
		trojanReq := fmt.Sprintf("%s\r\n\x01\x03\x0bexample.com\x00\x50\r\n", hex.EncodeToString(fakeHash[:]))
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		conn.Write([]byte(trojanReq))
		resp, _ := readWithTimeout(conn, shortTimeout)
		ch1 <- probeOut{resp: resp, hasHTTP: len(resp) > 0 && strings.Contains(string(resp), "HTTP/")}
	}()

	// Probe 2: Plain HTTP GET
	go func() {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			ch2 <- probeOut{}
			return
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + HostForHTTP(host) + "\r\n\r\n"))
		resp, _ := readWithTimeout(conn, shortTimeout)
		ch2 <- probeOut{resp: resp, hasHTTP: len(resp) > 0 && strings.Contains(string(resp), "HTTP/")}
	}()

	r1, r2 := <-ch1, <-ch2

	if r1.hasHTTP && r2.hasHTTP {
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 65}}
	}
	if !r1.hasHTTP && r2.hasHTTP {
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 75}}
	}
	if r1.hasHTTP && !r2.hasHTTP {
		return []ProbeResult{{Protocol: "Trojan", Transport: "TLS", Confidence: 65}}
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

	resp, err := readWithTimeout(conn, shortTimeout)

	if len(resp) == 0 && err != nil {
		// Connection closed with no data — too ambiguous without corroborating evidence
		return nil
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
	conn.Write(payload)

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
