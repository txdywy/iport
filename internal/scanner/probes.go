package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"github.com/quic-go/quic-go"
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

// Ping sends an ICMP Echo Request
func Ping(host string, timeout time.Duration) (error, time.Duration) {
	// Resolve IP
	ips, err := net.LookupIP(host)
	if err != nil {
		return err, 0
	}

	var ip net.IP
	for _, i := range ips {
		if i.To4() != nil {
			ip = i
			break
		}
	}
	if ip == nil {
		return fmt.Errorf("no IPv4 address found"), 0
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("icmp listen requires root privileges"), 0
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
		return err, 0
	}

	start := time.Now()
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: ip}); err != nil {
		return err, 0
	}

	c.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	n, _, err := c.ReadFrom(rb)
	if err != nil {
		return fmt.Errorf("timeout"), 0
	}
	rtt := time.Since(start)

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return err, 0
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		return nil, rtt
	default:
		return fmt.Errorf("unexpected ICMP type: %v", rm.Type), 0
	}
}

// CheckTLS checks if a specific TLS version is supported
func CheckTLS(host string, port string, version uint16, timeout time.Duration) (error, string) {
	target := net.JoinHostPort(host, port)

	conf := &tls.Config{
		InsecureSkipVerify: true, // We just want to check support, not validate cert
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         host,
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", target, conf)
	if err != nil {
		return err, ""
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return nil, tls.CipherSuiteName(state.CipherSuite)
}

// CheckHTTP checks standard HTTP/HTTPS and ALPN negotiation
func CheckHTTP(host string, port string, timeout time.Duration) (error, string) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	target := net.JoinHostPort(host, port)

	// If it's a standard web port, we might not need the port in the URL
	urlHost := host
	if port != "80" && port != "443" {
		urlHost = target
	}

	resp, err := client.Get("https://" + urlHost)
	if err != nil {
		// Fallback to HTTP if HTTPS fails
		resp, err = client.Get("http://" + urlHost)
		if err != nil {
			return err, ""
		}
	}
	defer resp.Body.Close()

	proto := resp.Proto
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		proto = resp.TLS.NegotiatedProtocol
	}

	return nil, fmt.Sprintf("%s (Status: %d)", proto, resp.StatusCode)
}

// CheckHTTP3 checks QUIC / HTTP3 support
func CheckHTTP3(host string, port string, timeout time.Duration) error {
	target := net.JoinHostPort(host, port)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	// Try QUIC dial
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, target, tlsConf, &quic.Config{})
	if err != nil {
		return err
	}
	conn.CloseWithError(0, "")
	return nil
}
