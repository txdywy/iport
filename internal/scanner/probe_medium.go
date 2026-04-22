package scanner

import (
	"crypto/rand"
	"net"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"Shadowsocks", probeShadowsocks},
		NamedProbe{"VMess", probeVMess},
	)
}

// probeShadowsocks detects Shadowsocks AEAD by sending a fake salt+payload and analyzing behavior.
// SS-AEAD servers: receive 32-byte salt + encrypted payload, fail auth silently (close or no response).
// Normal services: typically respond with error/banner or keep connection open differently.
func probeShadowsocks(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// Send 50 bytes: 32-byte salt + 18-byte encrypted length chunk (mimics AEAD format)
	payload := make([]byte, 50)
	rand.Read(payload)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	// SS behavior: invalid AEAD auth → server reads, fails decrypt, closes connection
	// Typical timing: close within ~100ms with no response data
	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)

	if n == 0 && err != nil {
		// Connection closed with no data — consistent with SS AEAD auth failure
		// But also consistent with many other services, so moderate confidence
		// Additional signal: send a second probe with different size to distinguish
		conn2, err2 := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
		if err2 != nil {
			return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TCP", Confidence: 40}}
		}
		defer conn2.Close()

		// Send just 10 bytes (too short for valid SS AEAD salt)
		small := make([]byte, 10)
		rand.Read(small)
		conn2.SetWriteDeadline(time.Now().Add(shortTimeout))
		conn2.Write(small)
		conn2.SetReadDeadline(time.Now().Add(shortTimeout))
		n2, _ := conn2.Read(resp)

		if n2 == 0 {
			// Both sizes cause silent close — stronger SS signal
			return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TCP", Confidence: 60}}
		}
		return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TCP", Confidence: 40}}
	}

	if n > 0 {
		// Got response data — check entropy
		entropy := ShannonEntropy(resp[:n])
		if entropy > 7.5 {
			// High entropy response to random data — could be SS with replay protection
			return []ProbeResult{{Protocol: "Shadowsocks", Transport: "TCP", Confidence: 45}}
		}
	}
	return nil
}

// probeVMess detects VMess by sending a crafted auth header and analyzing the response.
// VMess auth: 16-byte hash of (timestamp XOR UUID), then encrypted request header.
// Invalid auth → server typically closes connection after reading 16 bytes.
func probeVMess(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// VMess expects: 16-byte auth (HMAC of timestamp) + encrypted request header
	// Send 16 random bytes (invalid auth) + 40 random bytes (fake encrypted header)
	payload := make([]byte, 56)
	rand.Read(payload)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	elapsed := time.Since(start)

	if n == 0 && err != nil {
		// VMess with invalid auth: reads exactly 16 bytes for auth check, then closes
		// Distinguish from SS: VMess tends to close slightly faster after auth check
		if elapsed < shortTimeout/2 {
			return []ProbeResult{{Protocol: "VMess", Transport: "TCP", Confidence: 50}}
		}
		return []ProbeResult{{Protocol: "VMess", Transport: "TCP", Confidence: 35}}
	}

	if n > 0 && ShannonEntropy(resp[:n]) > 7.5 {
		return []ProbeResult{{Protocol: "VMess", Transport: "TCP", Confidence: 40}}
	}
	return nil
}
