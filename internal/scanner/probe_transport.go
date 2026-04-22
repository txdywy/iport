package scanner

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"WebSocket Transport", probeWebSocket},
		NamedProbe{"gRPC Transport", probeGRPC},
		NamedProbe{"HTTPUpgrade Transport", probeHTTPUpgrade},
		NamedProbe{"XHTTP Transport", probeXHTTP},
	)
}

// Common V2Ray WebSocket paths to probe
var wsPaths = []string{"/", "/ws", "/ray"}

// probeWebSocket detects WebSocket transport (used by V2Ray/Xray for VLESS/VMess/Trojan).
func probeWebSocket(host, port string, timeout time.Duration) []ProbeResult {
	for _, path := range wsPaths {
		if r := tryWSUpgrade(host, port, path, timeout); len(r) > 0 {
			return r
		}
	}
	return nil
}

func tryWSUpgrade(host, port, path string, timeout time.Duration) []ProbeResult {
	conn, err := dialTLSRaw(host, port, timeout)
	if err != nil {
		// Try plain TCP for non-TLS WebSocket
		tcpConn, err2 := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
		if err2 != nil {
			return nil
		}
		return doWSHandshake(tcpConn, host, path, timeout, "WebSocket")
	}
	return doWSHandshake(conn, host, path, timeout, "TLS+WebSocket")
}

func doWSHandshake(conn net.Conn, host, path string, timeout time.Duration, transport string) []ProbeResult {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Generate WebSocket key
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, wsKey)
	conn.Write([]byte(req))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}

	if strings.Contains(line, "101") {
		// Verify Sec-WebSocket-Accept
		expectedAccept := computeWSAccept(wsKey)
		for {
			hdr, err := reader.ReadString('\n')
			if err != nil || hdr == "\r\n" {
				break
			}
			if strings.HasPrefix(strings.ToLower(hdr), "sec-websocket-accept:") {
				got := strings.TrimSpace(strings.SplitN(hdr, ":", 2)[1])
				if got == expectedAccept {
					// Valid WebSocket upgrade — now try to detect inner protocol
					return detectWSInnerProtocol(conn, transport, path, timeout)
				}
			}
		}
		// 101 but no valid accept — still likely WS proxy
		return []ProbeResult{{Protocol: "Unknown", Transport: transport, Confidence: 70}}
	}
	return nil
}

func computeWSAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// detectWSInnerProtocol sends protocol-specific probes over the established WebSocket connection.
func detectWSInnerProtocol(conn net.Conn, transport, path string, timeout time.Duration) []ProbeResult {
	shortTimeout := timeout / 4
	if shortTimeout < 300*time.Millisecond {
		shortTimeout = 300 * time.Millisecond
	}

	// Try VLESS probe over WS
	header := make([]byte, 0, 64)
	header = append(header, 0x00) // VLESS version
	uuid := make([]byte, 16)
	rand.Read(uuid)
	header = append(header, uuid...)
	header = append(header, 0x00)                       // addons len
	header = append(header, 0x01)                       // cmd TCP
	header = append(header, 0x00, 0x50)                 // port 80
	header = append(header, 0x02, 0x0b)                 // domain type, len 11
	header = append(header, []byte("example.com")...)

	// Wrap in WebSocket binary frame
	wsFrame := makeWSFrame(header)
	conn.SetWriteDeadline(time.Now().Add(shortTimeout))
	conn.Write(wsFrame)

	conn.SetReadDeadline(time.Now().Add(shortTimeout))
	resp := make([]byte, 256)
	n, _ := conn.Read(resp)

	proto := "Proxy"
	confidence := 75.0

	if n > 0 {
		// Check if response looks like VLESS response (version=0)
		payload := extractWSPayload(resp[:n])
		if len(payload) > 0 && payload[0] == 0x00 {
			proto = "VLESS"
			confidence = 85
		}
	}

	// Infer protocol from path
	pathLower := strings.ToLower(path)
	if strings.Contains(pathLower, "vmess") {
		proto = "VMess"
	} else if strings.Contains(pathLower, "vless") {
		proto = "VLESS"
	} else if strings.Contains(pathLower, "trojan") {
		proto = "Trojan"
	}

	return []ProbeResult{{Protocol: proto, Transport: transport, Confidence: confidence}}
}

// makeWSFrame wraps payload in a WebSocket binary frame (unmasked for simplicity).
func makeWSFrame(payload []byte) []byte {
	frame := []byte{0x82} // FIN + binary opcode
	l := len(payload)
	if l < 126 {
		frame = append(frame, byte(l)|0x80) // masked
	} else {
		frame = append(frame, 126|0x80, byte(l>>8), byte(l))
	}
	// Mask key
	mask := make([]byte, 4)
	rand.Read(mask)
	frame = append(frame, mask...)
	masked := make([]byte, l)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	return append(frame, masked...)
}

// extractWSPayload extracts payload from a WebSocket frame (simplified).
func extractWSPayload(frame []byte) []byte {
	if len(frame) < 2 {
		return nil
	}
	payloadLen := int(frame[1] & 0x7F)
	offset := 2
	if payloadLen == 126 && len(frame) >= 4 {
		payloadLen = int(frame[2])<<8 | int(frame[3])
		offset = 4
	}
	masked := frame[1]&0x80 != 0
	if masked {
		offset += 4
	}
	if offset+payloadLen > len(frame) {
		payloadLen = len(frame) - offset
	}
	if payloadLen <= 0 {
		return nil
	}
	data := frame[offset : offset+payloadLen]
	if masked && offset >= 6 {
		mask := frame[offset-4 : offset]
		for i := range data {
			data[i] ^= mask[i%4]
		}
	}
	return data
}

// probeGRPC detects gRPC transport (used by V2Ray/Xray).
func probeGRPC(host, port string, timeout time.Duration) []ProbeResult {
	t := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: host},
		ForceAttemptHTTP2: true,
	}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: timeout}

	for _, svc := range []string{"/grpc", "/GunService/Tun", "/vless", "/vmess"} {
		url := fmt.Sprintf("https://%s:%s%s", host, port, svc)
		req, _ := http.NewRequest("POST", url, nil)
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.Header.Get("Content-Type") == "application/grpc" ||
			resp.Header.Get("Grpc-Status") != "" {
			proto := "Proxy"
			if strings.Contains(svc, "vless") {
				proto = "VLESS"
			} else if strings.Contains(svc, "vmess") {
				proto = "VMess"
			}
			return []ProbeResult{{Protocol: proto, Transport: "TLS+gRPC", Confidence: 70}}
		}
	}
	return nil
}

// probeHTTPUpgrade detects V2Ray HTTPUpgrade transport.
// Uses independent connection per path to avoid corrupted state.
func probeHTTPUpgrade(host, port string, timeout time.Duration) []ProbeResult {
	for _, path := range []string{"/", "/httpupgrade", "/upgrade"} {
		conn, err := dialTLSRaw(host, port, timeout)
		if err != nil {
			return nil
		}
		conn.SetDeadline(time.Now().Add(timeout))

		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			path, host)
		conn.Write([]byte(req))

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		conn.Close()
		if err != nil {
			continue
		}
		if strings.Contains(line, "101") {
			return []ProbeResult{{Protocol: "Proxy", Transport: "TLS+HTTPUpgrade", Confidence: 70}}
		}
	}
	return nil
}

// probeXHTTP detects Xray XHTTP transport.
// XHTTP uses HTTP POST for upload and GET with streaming for download.
func probeXHTTP(host, port string, timeout time.Duration) []ProbeResult {
	t := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: host},
		ForceAttemptHTTP2: true,
	}
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, Timeout: timeout}

	// XHTTP typically uses POST with chunked encoding to specific paths
	for _, path := range []string{"/", "/xhttp", "/post"} {
		url := fmt.Sprintf("https://%s:%s%s", host, port, path)

		// Try POST — XHTTP servers accept POST and stream response
		req, _ := http.NewRequest("POST", url, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		ct := resp.Header.Get("Content-Type")
		te := resp.Header.Get("Transfer-Encoding")
		resp.Body.Close()

		// XHTTP signals: accepts POST with octet-stream, returns chunked/streaming
		if resp.StatusCode == 200 && (ct == "application/octet-stream" || te == "chunked") {
			return []ProbeResult{{Protocol: "Proxy", Transport: "TLS+XHTTP", Confidence: 60}}
		}
	}
	return nil
}
