package scanner

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// TLSInfo holds metadata extracted from a TLS handshake for protocol fingerprinting.
type TLSInfo struct {
	Version           uint16
	CipherSuite       uint16
	ALPN              string
	CertCN            string
	CertSANs          []string
	CertIPs           []net.IP
	JA3SHash          string
	HandshakeDuration time.Duration
	Conn              *tls.Conn // live connection for further probing
}

// AnalyzeTLS connects with TLS and extracts fingerprint metadata.
// Caller must close info.Conn when done.
func AnalyzeTLS(host, port string, timeout time.Duration) (*TLSInfo, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}

	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), conf)
	if err != nil {
		return nil, err
	}
	dur := time.Since(start)

	state := conn.ConnectionState()
	info := &TLSInfo{
		Version:           state.Version,
		CipherSuite:       state.CipherSuite,
		ALPN:              state.NegotiatedProtocol,
		HandshakeDuration: dur,
		Conn:              conn,
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CertCN = cert.Subject.CommonName
		info.CertSANs = cert.DNSNames
		info.CertIPs = cert.IPAddresses
	}

	info.JA3SHash = computeJA3S(state)
	return info, nil
}

// computeJA3S generates a simplified JA3S-like hash from the server's TLS state.
func computeJA3S(state tls.ConnectionState) string {
	// JA3S = md5(TLSVersion,CipherSuite,Extensions)
	// We use sha256 truncated for a simpler fingerprint
	raw := fmt.Sprintf("%d,%d,%s", state.Version, state.CipherSuite, state.NegotiatedProtocol)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:12])
}

// CertMatchesHost checks if the TLS certificate matches the target host.
// Returns false if cert CN/SANs don't match — a signal for Reality/domain-fronting.
func CertMatchesHost(info *TLSInfo, host string) bool {
	// If target is an IP, check cert IP SANs
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range info.CertIPs {
			if certIP.Equal(ip) {
				return true
			}
		}
		return false
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if matchesDomain(info.CertCN, host) {
		return true
	}
	for _, san := range info.CertSANs {
		if matchesDomain(san, host) {
			return true
		}
	}
	return false
}

func matchesDomain(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if pattern == host {
		return true
	}
	// wildcard: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		if strings.HasSuffix(host, suffix) && !strings.Contains(host[:len(host)-len(suffix)], ".") {
			return true
		}
	}
	return false
}

// ShannonEntropy computes the Shannon entropy of data (0-8 bits per byte).
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// dialTLSRaw connects with TLS and returns the live connection for protocol probing.
// This is a lighter version of AnalyzeTLS when we don't need full metadata.
func dialTLSRaw(host, port string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
}

// readWithTimeout reads from conn with a short timeout, returns data read and any error.
func readWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], err
	}
	return nil, err
}
