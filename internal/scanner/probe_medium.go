package scanner

import (
	"crypto/rand"
	"net"
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
// Key insight from SIP022 spec §3.1.4 "Detection Prevention":
// - SS2022 servers MUST NOT close immediately on invalid data — they drain/read-forever
// - SS2022 uses fixed salt sizes: 16 bytes (AES-128-GCM) or 32 bytes (AES-256-GCM)
// - Server reads exactly salt + fixed-header-chunk before AEAD validation
//
// Detection strategy (3 concurrent probes):
// 1. Send short data (< min salt size) → SS waits for more data (timeout, no close)
// 2. Send medium data (50 bytes, covers both salt sizes) → SS reads, fails AEAD, drains
// 3. Send HTTP GET → SS treats as random data, same drain behavior (no HTTP response)
//
// If all 3 probes show "no response, no close" or "drain" behavior, and probe 3
// does NOT return HTTP → strong SS signal. Normal services would respond to HTTP.
func probeShadowsocks(host, port string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	type probeResult struct {
		gotData   bool
		gotClose  bool // connection closed/reset before timeout
		gotRST    bool // connection reset (RST) specifically
		gotHTTP   bool
		entropy   float64
		closeTime time.Duration
	}

	doProbe := func(payload []byte) probeResult {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
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

		r := probeResult{closeTime: elapsed}
		if n > 0 {
			r.gotData = true
			r.entropy = ShannonEntropy(resp[:n])
			if n >= 4 && string(resp[:4]) == "HTTP" {
				r.gotHTTP = true
			}
		}
		if err != nil {
			errStr := err.Error()
			if elapsed < shortTimeout-100*time.Millisecond {
				r.gotClose = true
			}
			// Detect RST specifically — SS2022 SO_LINGER(0) strategy
			if strings.Contains(errStr, "connection reset") {
				r.gotClose = true
				r.gotRST = true
			}
		}
		return r
	}

	// Run 3 probes concurrently
	ch1 := make(chan probeResult, 1)
	ch2 := make(chan probeResult, 1)
	ch3 := make(chan probeResult, 1)

	// Probe 1: Short payload (8 bytes — less than any SS salt size)
	go func() {
		p := make([]byte, 8)
		rand.Read(p)
		ch1 <- doProbe(p)
	}()

	// Probe 2: Medium payload (50 bytes — covers 32-byte salt + partial header)
	go func() {
		p := make([]byte, 50)
		rand.Read(p)
		ch2 <- doProbe(p)
	}()

	// Probe 3: HTTP GET — normal HTTP servers respond, SS treats as random data
	go func() {
		ch3 <- doProbe([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
	}()

	r1, r2, r3 := <-ch1, <-ch2, <-ch3

	confidence := 0.0

	// SS2022 signature: server drains on all probes (no data back, no quick close)
	// "no data, no close" = timeout on read = server is draining/reading-forever
	noDataNoClose := func(r probeResult) bool {
		return !r.gotData && !r.gotClose
	}

	if noDataNoClose(r1) && noDataNoClose(r2) && noDataNoClose(r3) {
		// All 3 probes: server absorbed data silently and kept connection open
		// This is the classic SS2022 "read forever" / "shutdown(SHUT_WR)" behavior
		confidence = 80
	} else if noDataNoClose(r1) && noDataNoClose(r2) && !r3.gotHTTP {
		// Short + medium absorbed, HTTP probe also no HTTP response
		confidence = 75
	} else if !r1.gotData && !r2.gotData && !r3.gotData && r1.gotRST && r2.gotRST && r3.gotRST {
		// All 3 probes: no data, all RST — SS2022 SO_LINGER(0) strategy
		// Server reads data, fails AEAD, immediately RSTs
		confidence = 75
	} else if !r1.gotData && !r2.gotData && !r3.gotHTTP && r2.gotRST {
		// Medium probe RST, no HTTP response — likely SS with SO_LINGER
		confidence = 65
	} else if !r1.gotData && !r2.gotData && !r3.gotHTTP {
		// No data on any probe, HTTP didn't get HTTP response
		if r1.gotClose && r2.gotClose {
			// Both closed quickly — legacy SS AEAD or SS2022
			confidence = 55
		} else {
			confidence = 50
		}
	} else if !r2.gotData && r2.gotClose && !r3.gotHTTP && r3.gotClose {
		confidence = 40
	}

	// Negative signal: if HTTP probe got actual HTTP response, it's not SS
	if r3.gotHTTP {
		return nil
	}

	// Negative signal: if any probe got low-entropy data, it's likely a normal service
	for _, r := range []probeResult{r1, r2, r3} {
		if r.gotData && r.entropy < 6.0 {
			return nil
		}
	}

	if confidence >= 40 {
		proto := "Shadowsocks"
		if noDataNoClose(r1) && noDataNoClose(r2) {
			proto = "Shadowsocks (2022)" // SS2022's distinctive drain behavior
		} else if r1.gotRST && r2.gotRST && r3.gotRST && !r1.gotData && !r2.gotData && !r3.gotData {
			proto = "Shadowsocks (2022)" // SS2022's SO_LINGER RST behavior
		}
		return []ProbeResult{{Protocol: proto, Transport: "TCP", Confidence: confidence}}
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
