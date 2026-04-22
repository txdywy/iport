package scanner

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"Reality", probeReality},
		NamedProbe{"XTLS-Vision", probeXTLSVision},
		NamedProbe{"ShadowTLS", probeShadowTLS},
		NamedProbe{"AnyTLS", probeAnyTLS},
		NamedProbe{"NaïveProxy", probeNaiveProxy},
	)
}

// probeReality detects VLESS+Reality by analyzing TLS certificate mismatch.
// Reality borrows a real website's TLS certificate, so the cert CN/SANs won't match the target.
// Combined with TLS 1.3 requirement and specific cipher suites.
func probeReality(host, port string, timeout time.Duration) []ProbeResult {
	info, err := AnalyzeTLS(host, port, timeout)
	if err != nil {
		return nil
	}
	defer info.Conn.Close()

	if info.Version != tls.VersionTLS13 {
		return nil
	}

	if CertMatchesHost(info, host) {
		return nil
	}

	confidence := 40.0

	switch info.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		confidence += 5
	}

	// IP-vs-SNI mismatch: resolve the cert's domain and compare with target IP.
	// Reality borrows certs from real sites, so the cert domain resolves to different IPs.
	targetIPs, _ := net.LookupIP(host)
	certDomain := info.CertCN
	if len(info.CertSANs) > 0 {
		certDomain = info.CertSANs[0]
	}
	if certDomain != "" {
		certIPs, err := net.LookupIP(certDomain)
		if err == nil && len(certIPs) > 0 && len(targetIPs) > 0 {
			match := false
			for _, tip := range targetIPs {
				for _, cip := range certIPs {
					if tip.Equal(cip) {
						match = true
					}
				}
			}
			if !match {
				confidence += 15 // cert domain resolves to different IP → strong Reality signal
			}
		}
	}

	// VLESS probe over this connection
	header := make([]byte, 0, 64)
	header = append(header, 0x00)
	uuid := make([]byte, 16)
	rand.Read(uuid)
	header = append(header, uuid...)
	header = append(header, 0x00, 0x01, 0x00, 0x50, 0x02, 0x0b)
	header = append(header, []byte("example.com")...)

	shortTimeout := timeout / 3
	info.Conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	info.Conn.Write(header)

	resp, _ := readWithTimeout(info.Conn, shortTimeout)
	if len(resp) >= 2 && resp[0] == 0x00 {
		confidence += 15 // got VLESS response
	}

	return []ProbeResult{{Protocol: "VLESS+Reality", Transport: "TLS 1.3", Confidence: confidence}}
}

// probeXTLSVision detects VLESS with XTLS-Vision flow control.
// Vision adds padding to inner TLS records to disguise TLS-in-TLS patterns.
// Detection: connect with TLS, send VLESS header with flow="xtls-rprx-vision", analyze response.
func probeXTLSVision(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// VLESS header with flow addon "xtls-rprx-vision"
	flow := "xtls-rprx-vision"
	header := make([]byte, 0, 128)
	header = append(header, 0x00) // version
	uuid := make([]byte, 16)
	rand.Read(uuid)
	header = append(header, uuid...)

	// Addons: protobuf-like encoding for flow field
	// Simplified: length-prefixed flow string
	addonPayload := []byte{0x0a, byte(len(flow))}
	addonPayload = append(addonPayload, []byte(flow)...)
	header = append(header, byte(len(addonPayload)))
	header = append(header, addonPayload...)

	header = append(header, 0x01)                       // cmd TCP
	header = append(header, 0x00, 0x50)                 // port 80
	header = append(header, 0x02, 0x0b)                 // domain, len 11
	header = append(header, []byte("example.com")...)

	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn.Write(header)

	resp, err := readWithTimeout(conn, shortTimeout)
	if len(resp) > 0 && resp[0] == 0x00 {
		// Got VLESS response — server accepted the flow
		return []ProbeResult{{Protocol: "VLESS+XTLS-Vision", Transport: "TLS", Confidence: 55}}
	}
	if len(resp) == 0 && err != nil {
		// Silent close — could be VLESS with Vision rejecting invalid UUID
		return []ProbeResult{{Protocol: "VLESS+XTLS-Vision", Transport: "TLS", Confidence: 40}}
	}
	return nil
}

// probeShadowTLS detects ShadowTLS v3 by analyzing TLS handshake behavior.
// ShadowTLS relays the TLS handshake to a real server, then switches to proxy mode.
// Detection: TLS 1.3 + valid cert from a well-known site + specific timing patterns.
func probeShadowTLS(host, port string, timeout time.Duration) []ProbeResult {
	info, err := AnalyzeTLS(host, port, timeout)
	if err != nil {
		return nil
	}
	defer info.Conn.Close()

	// ShadowTLS requires TLS 1.3 (strict mode)
	if info.Version != tls.VersionTLS13 {
		return nil
	}

	// ShadowTLS uses a real server's cert — cert should be valid for a well-known domain
	// but NOT for our target host (unless target IS the handshake server)
	if CertMatchesHost(info, host) {
		// Cert matches target — could still be ShadowTLS if target is the handshake server
		// Lower confidence
		return nil
	}

	confidence := 35.0

	// ShadowTLS handshake is relayed, so timing may be slightly longer than direct TLS
	if info.HandshakeDuration > 200*time.Millisecond {
		confidence += 5
	}

	// After TLS handshake, ShadowTLS expects client to send data with HMAC prefix
	// Send random data — ShadowTLS will fail HMAC check and close
	randomData := make([]byte, 32)
	rand.Read(randomData)
	info.Conn.SetWriteDeadline(time.Now().Add(timeout / 3))
	info.Conn.Write(randomData)

	_, err = readWithTimeout(info.Conn, timeout/3)
	if err != nil {
		// Connection closed after invalid HMAC — consistent with ShadowTLS
		confidence += 10
	}

	return []ProbeResult{{Protocol: "ShadowTLS", Transport: "TLS 1.3", Confidence: confidence}}
}

// probeAnyTLS detects AnyTLS by analyzing TLS session multiplexing behavior.
// AnyTLS maintains a pool of TLS sessions and multiplexes connections.
// Detection: make multiple rapid TLS connections and check for session reuse patterns.
func probeAnyTLS(host, port string, timeout time.Duration) []ProbeResult {
	// AnyTLS: after TLS, client sends sha256(password) (32 bytes) + padding_length (2B) + padding.
	// Detection: send <32 bytes → server waits for more (timeout).
	// Send >=32 bytes random → server fails auth, closes or falls back.
	// Compare behavior.

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	type probeOut struct {
		noData    bool
		gotClose  bool
		latencyMs int64
	}

	doProbe := func(size int) probeOut {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			return probeOut{noData: true, gotClose: true}
		}
		defer conn.Close()
		data := make([]byte, size)
		rand.Read(data)
		conn.SetWriteDeadline(time.Now().Add(shortTimeout))
		conn.Write(data)
		start := time.Now()
		resp, err := readWithTimeout(conn, shortTimeout)
		elapsed := time.Since(start)
		return probeOut{
			noData:    len(resp) == 0,
			gotClose:  err != nil && elapsed < shortTimeout-100*time.Millisecond,
			latencyMs: elapsed.Milliseconds(),
		}
	}

	ch1 := make(chan probeOut, 1) // short: 16 bytes (< 32 auth threshold)
	ch2 := make(chan probeOut, 1) // full: 48 bytes (>= 32 auth + padding header)
	go func() { ch1 <- doProbe(16) }()
	go func() { ch2 <- doProbe(48) }()

	short, full := <-ch1, <-ch2

	confidence := 0.0

	// AnyTLS signature: short probe times out (server waiting for 32B), full probe closes quickly
	if short.noData && !short.gotClose && full.noData && full.gotClose {
		confidence = 60 // server buffered short, rejected full
	} else if short.noData && !short.gotClose && full.noData && !full.gotClose {
		confidence = 50 // both timeout — server waiting for valid framing
	} else if short.latencyMs > full.latencyMs+100 {
		confidence = 45 // short notably slower than full
	}

	// Also check cert mismatch
	if confidence > 0 {
		info, err := AnalyzeTLS(host, port, timeout)
		if err == nil {
			if !CertMatchesHost(info, host) {
				confidence += 10
			}
			info.Conn.Close()
		}
	}

	if confidence >= 40 {
		return []ProbeResult{{Protocol: "AnyTLS", Transport: "TLS", Confidence: confidence}}
	}
	return nil
}

// probeNaiveProxy detects NaïveProxy by checking for HTTP/2 proxy behavior.
// NaïveProxy uses HTTP/2 CONNECT method with proxy authentication.
// Detection: TLS + ALPN h2 + HTTP/2 CONNECT → expect 407 Proxy Authentication Required.
func probeNaiveProxy(host, port string, timeout time.Duration) []ProbeResult {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2"},
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", net.JoinHostPort(host, port), tlsConf)
	if err != nil {
		return nil
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil
	}

	// Use HTTP/2 to send CONNECT request (NaïveProxy style)
	t := &http2.Transport{TLSClientConfig: tlsConf}
	defer t.CloseIdleConnections()

	url := "https://" + URLHost(host, port)
	req, _ := http.NewRequest("CONNECT", url, nil)
	req.Host = "example.com:443"

	client := &http.Client{Transport: t, Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		// Some NaïveProxy configs may reject malformed CONNECT
		if strings.Contains(err.Error(), "407") {
			return []ProbeResult{{Protocol: "NaïveProxy", Transport: "TLS+H2", Confidence: 70}}
		}
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case 407:
		// Proxy Authentication Required — strong NaïveProxy signal
		return []ProbeResult{{Protocol: "NaïveProxy", Transport: "TLS+H2", Confidence: 70}}
	case 200:
		// Open proxy via H2 CONNECT — could be NaïveProxy without auth
		return []ProbeResult{{Protocol: "NaïveProxy", Transport: "TLS+H2", Confidence: 55}}
	case 403, 401:
		return []ProbeResult{{Protocol: "NaïveProxy", Transport: "TLS+H2", Confidence: 50}}
	}
	return nil
}
