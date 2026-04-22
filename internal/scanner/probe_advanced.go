package scanner

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
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

	// Reality requires TLS 1.3
	if info.Version != tls.VersionTLS13 {
		return nil
	}

	// Check cert mismatch — the key Reality signal
	if CertMatchesHost(info, host) {
		return nil // Cert matches, not Reality
	}

	confidence := 40.0

	// Reality uses specific cipher suites
	switch info.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		confidence += 10
	}

	// Try VLESS probe over this TLS connection to confirm
	header := make([]byte, 0, 64)
	header = append(header, 0x00) // VLESS version
	uuid := make([]byte, 16)
	rand.Read(uuid)
	header = append(header, uuid...)
	header = append(header, 0x00)                       // addons len
	header = append(header, 0x01)                       // cmd TCP
	header = append(header, 0x00, 0x50)                 // port 80
	header = append(header, 0x02, 0x0b)                 // domain, len 11
	header = append(header, []byte("example.com")...)

	shortTimeout := timeout / 3
	info.Conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	info.Conn.Write(header)

	resp, err := readWithTimeout(info.Conn, shortTimeout)
	if len(resp) == 0 && err != nil {
		// Silent close on invalid UUID — consistent with VLESS+Reality
		confidence += 10
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
	// First connection — establish baseline
	info1, err := AnalyzeTLS(host, port, timeout)
	if err != nil {
		return nil
	}
	info1.Conn.Close()

	// Second connection — check for session ticket reuse
	info2, err := AnalyzeTLS(host, port, timeout)
	if err != nil {
		return nil
	}
	defer info2.Conn.Close()

	confidence := 0.0

	// AnyTLS uses TLS with session pooling
	if info1.Version == tls.VersionTLS13 && info2.Version == tls.VersionTLS13 {
		confidence += 20
	}

	// Check cert mismatch (AnyTLS may or may not use its own cert)
	if !CertMatchesHost(info2, host) {
		confidence += 10
	}

	// Send random data — AnyTLS expects its own framing protocol
	randomData := make([]byte, 32)
	rand.Read(randomData)
	info2.Conn.SetWriteDeadline(time.Now().Add(timeout / 3))
	info2.Conn.Write(randomData)

	_, err = readWithTimeout(info2.Conn, timeout/3)
	if err != nil {
		// Connection closed on invalid framing — consistent with AnyTLS
		confidence += 15
	}

	if confidence >= 35 {
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

	url := fmt.Sprintf("https://%s:%s", host, port)
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
