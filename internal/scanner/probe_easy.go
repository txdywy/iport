package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func init() {
	AllTCPProbes = append(AllTCPProbes,
		NamedProbe{"SOCKS5", probeSOCKS5},
		NamedProbe{"HTTP Proxy", probeHTTPProxy},
		NamedProbe{"SSH Tunnel", probeSSH},
	)
}

func probeSOCKS5(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting: version=5, 1 auth method, no-auth
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil
	}
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return nil
	}
	// buf[1]: 0x00=no-auth, 0x02=user/pass, 0xFF=no acceptable
	if buf[1] == 0xFF {
		return nil
	}
	return []ProbeResult{{Protocol: "SOCKS5", Transport: "TCP", Confidence: 95}}
}

func probeHTTPProxy(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil
	}
	if strings.HasPrefix(line, "HTTP/") {
		// Check status code: 200=open proxy, 407=auth required → confirm proxy
		// 400/405/501 = normal HTTP server rejecting CONNECT → NOT a proxy
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			code := parts[1]
			if code == "200" || code == "407" {
				return []ProbeResult{{Protocol: "HTTP Proxy", Transport: "TCP", Confidence: 95}}
			}
		}
	}
	return nil
}

func probeSSH(host, port string, timeout time.Duration) []ProbeResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}
	if strings.HasPrefix(string(buf[:n]), "SSH-") {
		return []ProbeResult{{Protocol: "SSH Tunnel", Transport: "TCP", Confidence: 99}}
	}
	return nil
}
