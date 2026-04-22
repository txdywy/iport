package scanner

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"Snell", probeSnell},
		NamedProbe{"obfs4", probeObfs4},
		NamedProbe{"Brook", probeBrook},
	)
}

// probeSnell detects Snell proxy protocol.
// Snell v3 uses AEAD encryption. The handshake starts with a version byte + command.
// Snell v1/v2: version(1) + command(1) + AEAD encrypted payload
// Invalid auth → server closes connection silently.
func probeSnell(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// Snell v3 header: version=3, then AEAD encrypted stream
	// Send a Snell-like header with invalid encryption
	payload := make([]byte, 48)
	payload[0] = 0x03 // version 3
	payload[1] = 0x01 // command: connect
	rand.Read(payload[2:])

	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)

	if n == 0 && err != nil {
		// Silent close — too ambiguous without corroborating evidence
		return nil
	}

	// Snell v1 may respond with version byte
	if n > 0 && (resp[0] == 0x01 || resp[0] == 0x02 || resp[0] == 0x03) {
		return []ProbeResult{{Protocol: "Snell", Transport: "TCP", Confidence: 65}}
	}
	return nil
}

// probeObfs4 detects obfs4 (Tor pluggable transport).
// obfs4 uses a Curve25519+Elligator2 handshake with specific framing.
// The client sends a padded handshake message with a specific structure.
// Detection: send random data of obfs4 handshake size, analyze response timing and pattern.
func probeObfs4(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// obfs4 client handshake: 32-byte Elligator2 representative + HMAC + padding
	// Total size: 8192 bytes max, minimum ~96 bytes
	// Send a probe that mimics the size range
	var rndByte [1]byte
	rand.Read(rndByte[:])
	probeSize := 96 + int(rndByte[0])%128
	payload := make([]byte, probeSize)
	rand.Read(payload)

	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 8192)
	n, err := conn.Read(resp)

	if n == 0 && err != nil {
		// obfs4 with invalid handshake: may wait for more data or close
		return nil
	}

	if n > 0 {
		entropy := ShannonEntropy(resp[:n])
		// obfs4 response should be high entropy (encrypted)
		// and within typical handshake response size (32-8192 bytes)
		if entropy > 7.5 && n >= 32 {
			return []ProbeResult{{Protocol: "obfs4", Transport: "TCP (Tor PT)", Confidence: 60}}
		}
	}
	return nil
}

// probeBrook detects Brook proxy protocol.
// Brook can run in multiple modes: server (raw TCP), wsserver (WebSocket), wssserver (WSS).
// Raw TCP mode: uses a simple password-based encryption with nonce prefix.
// WebSocket mode: standard WS upgrade to specific paths.
func probeBrook(host, port string, timeout time.Duration) []ProbeResult {
	// Try WebSocket mode first (more common deployment)
	if r := probeBrookWS(host, port, timeout); len(r) > 0 {
		return r
	}
	// Try raw TCP mode
	return probeBrookTCP(host, port, timeout)
}

func probeBrookWS(host, port string, timeout time.Duration) []ProbeResult {
	var conn net.Conn
	tlsConn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		conn, err = dialTCP(host, port, timeout)
		if err != nil {
			return nil
		}
	} else {
		conn = tlsConn
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Brook WSS uses WebSocket upgrade to /ws path
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)
	req := fmt.Sprintf("GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", HostForHTTP(host), wsKey)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.Contains(line, "101") {
		return []ProbeResult{{Protocol: "Brook", Transport: "WebSocket", Confidence: 55}}
	}
	return nil
}

func probeBrookTCP(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := dialTCP(host, port, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	shortTimeout := timeout / 3
	if shortTimeout < 500*time.Millisecond {
		shortTimeout = 500 * time.Millisecond
	}

	// Brook raw TCP: 12-byte nonce + encrypted payload
	payload := make([]byte, 32)
	rand.Read(payload)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 256)
	n, err := conn.Read(resp)

	if n == 0 && err != nil {
		// Silent close — too ambiguous without corroborating evidence
		return nil
	}
	if n > 0 && ShannonEntropy(resp[:n]) > 7.5 {
		return []ProbeResult{{Protocol: "Brook", Transport: "TCP", Confidence: 45}}
	}
	return nil
}
