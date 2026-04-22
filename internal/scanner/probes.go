package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
)

func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "Unknown"
	}
}

// CheckTCP attempts to connect to a TCP port
func CheckTCP(host string, port string, timeout time.Duration) error {
	target := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// CheckUDP attempts to send a packet to a UDP port and waits for an ICMP unreachable.
// Note: This is a basic UDP check. Many firewalls silently drop UDP packets.
func CheckUDP(host string, port string, timeout time.Duration) error {
	target := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send a single-byte packet (empty write may be a no-op on some systems)
	if _, err = conn.Write([]byte{0}); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Now().Add(timeout))

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return fmt.Errorf("timeout (open|filtered)")
		}
		return err
	}
	return nil
}

// Ping sends an ICMP Echo Request
func Ping(host string, timeout time.Duration) (time.Duration, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return 0, err
	}

	var ip net.IP
	for _, i := range ips {
		if i.To4() != nil {
			ip = i
			break
		}
	}
	if ip == nil {
		return 0, fmt.Errorf("no IPv4 address found")
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, fmt.Errorf("icmp listen requires root privileges")
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-IPORT"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: ip}); err != nil {
		return 0, err
	}

	c.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return 0, fmt.Errorf("timeout")
	}
	rtt := time.Since(start)

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return 0, err
	}
	if rm.Type == ipv4.ICMPTypeEchoReply {
		return rtt, nil
	}
	return 0, fmt.Errorf("unexpected ICMP type: %v", rm.Type)
}

// CheckTLS checks if a specific TLS version is supported
func CheckTLS(host string, port string, version uint16, timeout time.Duration) (string, error) {
	target := net.JoinHostPort(host, port)

	conf := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         host,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return tls.CipherSuiteName(state.CipherSuite), nil
}

// CheckHTTP checks standard HTTP/HTTPS and ALPN negotiation
func CheckHTTP(host string, port string, timeout time.Duration) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Timeout: timeout, Transport: tr}

	// Determine scheme based on port
	scheme := "https"
	if port == "80" {
		scheme = "http"
	}

	urlHost := host
	if port != "80" && port != "443" {
		urlHost = net.JoinHostPort(host, port)
	}

	resp, err := client.Get(scheme + "://" + urlHost)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		// Fallback: try the other scheme for non-standard ports
		if port != "80" && port != "443" {
			alt := "http"
			if scheme == "http" {
				alt = "https"
			}
			resp, err = client.Get(alt + "://" + urlHost)
			if err != nil {
				if resp != nil {
					resp.Body.Close()
				}
				return "", err
			}
		} else {
			return "", err
		}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	proto := resp.Proto
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		proto = resp.TLS.NegotiatedProtocol
	}

	return fmt.Sprintf("%s (Status: %d)", proto, resp.StatusCode), nil
}

// CheckHTTP3 checks QUIC / HTTP3 support
func CheckHTTP3(host string, port string, timeout time.Duration) error {
	target := net.JoinHostPort(host, port)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, target, tlsConf, &quic.Config{})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	return nil
}
