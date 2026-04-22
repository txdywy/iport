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

// Sem is a global concurrency semaphore, set by main via SetSemaphore.
var sem chan struct{}

// SetSemaphore initializes the global concurrency limiter.
func SetSemaphore(concurrency int) {
	sem = make(chan struct{}, concurrency)
}

// acquire/release wrap the global semaphore. Safe to call if sem is nil.
func acquire() {
	if sem != nil {
		sem <- struct{}{}
	}
}
func release() {
	if sem != nil {
		<-sem
	}
}

// Singleton HTTP transport — reused across all CheckHTTP calls.
var sharedHTTPClient *http.Client

func init() {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:  true,
		MaxIdleConns:       100,
		IdleConnTimeout:    30 * time.Second,
		DisableKeepAlives:  false,
	}
	sharedHTTPClient = &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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

// CheckTCP attempts to connect to a TCP port using context for timeout control.
func CheckTCP(host, port string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// CheckUDP sends a packet to a UDP port and waits for an ICMP unreachable.
func CheckUDP(host, port string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	defer conn.Close()

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

// Ping sends an ICMP Echo Request, trying unprivileged UDP ping first,
// then falling back to raw socket (requires root).
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

	// Try unprivileged UDP ping first (works without root on most systems)
	if rtt, err := pingUDP(ip, timeout); err == nil {
		return rtt, nil
	}

	// Fallback to raw ICMP socket (requires root/CAP_NET_RAW)
	return pingRaw(ip, timeout)
}

func pingUDP(ip net.IP, timeout time.Duration) (time.Duration, error) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return doPing(c, &net.UDPAddr{IP: ip}, timeout)
}

func pingRaw(ip net.IP, timeout time.Duration) (time.Duration, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, fmt.Errorf("ping requires root privileges or unprivileged ICMP support")
	}
	defer c.Close()
	return doPing(c, &net.IPAddr{IP: ip}, timeout)
}

func doPing(c *icmp.PacketConn, dst net.Addr, timeout time.Duration) (time.Duration, error) {
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
	if _, err := c.WriteTo(wb, dst); err != nil {
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

// CheckTLS checks if a specific TLS version is supported.
func CheckTLS(host, port string, version uint16, timeout time.Duration) (string, error) {
	acquire()
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
			ServerName:         host,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	return tls.CipherSuiteName(state.CipherSuite), nil
}

// CheckHTTP checks standard HTTP/HTTPS and ALPN negotiation.
// Uses a singleton transport and proper context-based timeout.
func CheckHTTP(host, port string, timeout time.Duration) (string, error) {
	acquire()
	defer release()

	scheme := "https"
	if port == "80" {
		scheme = "http"
	}
	urlHost := host
	if port != "80" && port != "443" {
		urlHost = net.JoinHostPort(host, port)
	}

	proto, err := doHTTPGet(scheme, urlHost, timeout)
	if err != nil && port != "80" && port != "443" {
		// Fallback: try the other scheme for non-standard ports
		alt := "http"
		if scheme == "http" {
			alt = "https"
		}
		proto, err = doHTTPGet(alt, urlHost, timeout)
	}
	return proto, err
}

func doHTTPGet(scheme, urlHost string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", scheme+"://"+urlHost, nil)
	if err != nil {
		return "", err
	}

	resp, err := sharedHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	// Drain body (capped at 1MB to prevent infinite streams) BEFORE context cancel
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	proto := resp.Proto
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		proto = resp.TLS.NegotiatedProtocol
	}
	return fmt.Sprintf("%s (Status: %d)", proto, resp.StatusCode), nil
}

// CheckHTTP3 checks QUIC / HTTP3 support.
func CheckHTTP3(host, port string, timeout time.Duration) error {
	acquire()
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}, &quic.Config{})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	return nil
}
