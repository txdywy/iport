package scanner

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

func init() {
	AllUDPProbes = append(AllUDPProbes,
		NamedProbe{"WireGuard", probeWireGuard},
		NamedProbe{"Hysteria2", probeHysteria2},
		NamedProbe{"TUIC", probeTUIC},
		NamedProbe{"mKCP", probeMKCP},
	)
}

func probeWireGuard(host, port string, timeout time.Duration) []ProbeResult {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// WireGuard handshake initiation: type=1, reserved=0,0,0, sender_index=random, then 140 bytes
	pkt := make([]byte, 148)
	pkt[0] = 1 // message type: handshake initiation
	rand.Read(pkt[4:8])
	rand.Read(pkt[8:]) // fill rest with random (unencrypted_ephemeral + encrypted_static + etc)
	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	// WireGuard handshake response: type=2, 92 bytes total
	if n == 92 && buf[0] == 2 {
		return []ProbeResult{{Protocol: "WireGuard", Transport: "UDP", Confidence: 90}}
	}
	// Some WireGuard implementations may respond with cookie reply (type=3, 64 bytes)
	if n == 64 && buf[0] == 3 {
		return []ProbeResult{{Protocol: "WireGuard", Transport: "UDP", Confidence: 85}}
	}
	return nil
}

func probeHysteria2(host, port string, timeout time.Duration) []ProbeResult {
	return probeQUIC(host, port, timeout, []string{"h3"}, "Hysteria2", 75)
}

func probeTUIC(host, port string, timeout time.Duration) []ProbeResult {
	// TUIC v5 uses custom ALPN
	for _, alpn := range []string{"tuic-v5", "tuic"} {
		if r := probeQUIC(host, port, timeout, []string{alpn}, "TUIC", 80); len(r) > 0 {
			return r
		}
	}
	return nil
}

func probeQUIC(host, port string, timeout time.Duration, alpn []string, proto string, confidence float64) []ProbeResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(host, port), tlsConf, &quic.Config{
		MaxIdleTimeout: timeout,
	})
	if err != nil {
		return nil
	}
	defer conn.CloseWithError(0, "")

	negotiated := conn.ConnectionState().TLS.NegotiatedProtocol
	for _, a := range alpn {
		if negotiated == a {
			return []ProbeResult{{Protocol: proto, Transport: "QUIC", Confidence: confidence}}
		}
	}
	// QUIC connected but ALPN didn't match exactly — still suspicious
	return []ProbeResult{{Protocol: proto, Transport: "QUIC", Confidence: confidence * 0.6}}
}

func probeMKCP(host, port string, timeout time.Duration) []ProbeResult {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// mKCP SYN-like probe: conv_id(4) + cmd=SYN(1) + frg(1) + wnd(2) + ts(4) + sn(4) + una(4) + len(4)
	pkt := make([]byte, 24)
	binary.LittleEndian.PutUint32(pkt[0:4], 0x12345678) // conv id
	pkt[4] = 0x01                                        // cmd: SYN
	binary.LittleEndian.PutUint16(pkt[6:8], 1024)        // window
	binary.LittleEndian.PutUint32(pkt[8:12], uint32(time.Now().UnixMilli()))

	if _, err := conn.Write(pkt); err != nil {
		return nil
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	// mKCP response should have similar header structure, at least 24 bytes
	if n >= 24 {
		return []ProbeResult{{Protocol: "mKCP", Transport: "UDP/KCP", Confidence: 70}}
	}
	return nil
}
