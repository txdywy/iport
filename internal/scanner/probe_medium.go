package scanner

import (
	"crypto/rand"
	"strings"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"Shadowsocks", probeShadowsocks},
		NamedProbe{"VMess", probeVMess},
	)
}

// probeShadowsocks detects Shadowsocks (legacy AEAD and 2022) by multi-probe behavioral analysis.
//
// Key insight: SS runs on RAW TCP (not TLS). So if a port accepts TLS handshake → NOT SS.
// SS2022 servers either "read forever" (drain) or RST via SO_LINGER on invalid data.
// But many normal services also timeout or RST on garbage, so we need multiple signals:
//
// Probe 1: TLS handshake attempt → if succeeds, eliminate SS (it's a TLS service)
// Probe 2: Short random data (8B) → SS waits/drains, normal services may respond
// Probe 3: Medium random data (50B) → SS fails AEAD, drains/RSTs
// Probe 4: HTTP GET → normal HTTP servers respond, SS treats as random data
//
// SS signature: TLS fails + no data on random probes + no HTTP response
func probeShadowsocks(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	type probeResult struct {
		gotData  bool
		gotClose bool
		gotRST   bool
		gotHTTP  bool
		entropy  float64
	}

	doProbe := func(payload []byte) probeResult {
		conn, err := dialTCP(host, port, timeout)
		if err != nil {
			return probeResult{gotClose: true}
		}
		defer conn.Close()
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		if _, err := conn.Write(payload); err != nil {
			return probeResult{gotClose: true}
		}
		start := time.Now()
		conn.SetReadDeadline(time.Now().Add(shortTimeout))
		resp := make([]byte, 512)
		n, err := conn.Read(resp)
		elapsed := time.Since(start)
		r := probeResult{}
		if n > 0 {
			r.gotData = true
			r.entropy = ShannonEntropy(resp[:n])
			if n >= 4 && string(resp[:4]) == "HTTP" {
				r.gotHTTP = true
			}
		}
		if err != nil {
			if strings.Contains(err.Error(), "connection reset") {
				r.gotClose = true
				r.gotRST = true
			} else if elapsed < shortTimeout-100*time.Millisecond {
				r.gotClose = true
			}
		}
		return r
	}

	// Run all 4 probes concurrently
	chTLS := make(chan bool, 1)       // true = TLS handshake succeeded
	ch1 := make(chan probeResult, 1)  // 8B random
	ch2 := make(chan probeResult, 1)  // 50B random
	ch3 := make(chan probeResult, 1)  // HTTP GET

	// Probe 0: TLS handshake — if succeeds, this is a TLS service, NOT raw SS
	go func() {
		conn, err := dialTLSRaw(host, port, timeout)
		if err == nil {
			conn.Close()
			chTLS <- true
		} else {
			// Distinguish "TLS rejected" (connection worked but handshake failed)
			// from "can't connect" (timeout/network issue)
			errStr := err.Error()
			if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				chTLS <- true // treat timeout as "might be TLS" → not SS
			} else {
				chTLS <- false // TLS explicitly rejected → could be raw SS
			}
		}
	}()

	go func() {
		p := make([]byte, 8)
		rand.Read(p)
		ch1 <- doProbe(p)
	}()
	go func() {
		p := make([]byte, 50)
		rand.Read(p)
		ch2 <- doProbe(p)
	}()
	go func() {
		ch3 <- doProbe([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
	}()

	tlsOK := <-chTLS
	r1, r2, r3 := <-ch1, <-ch2, <-ch3

	// CRITICAL: if TLS handshake succeeded, this is NOT raw Shadowsocks
	// (SS-over-TLS is handled by a separate probe in probe_tls.go)
	if tlsOK {
		return nil
	}

	// Negative: if HTTP probe got HTTP response, it's an HTTP service
	if r3.gotHTTP {
		return nil
	}

	// Negative: if any probe got low-entropy data, it's a normal service with a banner
	for _, r := range []probeResult{r1, r2, r3} {
		if r.gotData && r.entropy < 6.0 {
			return nil
		}
	}

	confidence := 0.0
	noDataNoClose := func(r probeResult) bool { return !r.gotData && !r.gotClose }

	// SS2022 "read forever" / drain: all probes timeout with no data, no close
	if noDataNoClose(r1) && noDataNoClose(r2) && noDataNoClose(r3) {
		confidence = 75
	} else if noDataNoClose(r1) && noDataNoClose(r2) {
		confidence = 65
	} else if !r1.gotData && !r2.gotData && r1.gotRST && r2.gotRST {
		// SS2022 SO_LINGER: RST on both random probes, no data
		// But also need HTTP probe to NOT get RST (to distinguish from generic RST services)
		if !r3.gotRST {
			confidence = 65
		} else {
			// All RST including HTTP → could be any non-HTTP service (DNS, Redis, etc.)
			// Much weaker signal
			confidence = 35
		}
	} else if !r1.gotData && !r2.gotData && r1.gotClose && r2.gotClose {
		// Legacy SS: silent close on both
		confidence = 45
	}

	if confidence >= 40 {
		proto := "Shadowsocks"
		if noDataNoClose(r1) && noDataNoClose(r2) {
			proto = "Shadowsocks (2022)"
		}
		return []ProbeResult{{Protocol: proto, Transport: "TCP", Confidence: confidence}}
	}
	return nil
}

// probeVMess detects VMess by sending a crafted auth header and analyzing the response.
// VMess auth: 16-byte hash of (timestamp XOR UUID), then encrypted request header.
// Invalid auth → server typically closes connection after reading 16 bytes.
func probeVMess(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTCP(host, port, timeout)
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
		// VMess with invalid auth: silent close — but too ambiguous alone
		// Only report if timing is distinctively fast (< 200ms)
		if elapsed < 200*time.Millisecond {
			return []ProbeResult{{Protocol: "VMess", Transport: "TCP", Confidence: 35}}
		}
		return nil
	}

	if n > 0 && ShannonEntropy(resp[:n]) > 7.5 {
		return []ProbeResult{{Protocol: "VMess", Transport: "TCP", Confidence: 40}}
	}
	return nil
}
