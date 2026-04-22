package webcheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	attemptsPerCheck = 3
	maxTestIPs       = 2
)

type Verdict string

const (
	VerdictNormal       Verdict = "Normal"
	VerdictAbnormal     Verdict = "Abnormal"
	VerdictLikelyGFW    Verdict = "Likely GFW Interference"
	VerdictInconclusive Verdict = "Inconclusive"
)

type Target struct {
	Raw         string
	Scheme      string
	Host        string
	Port        string
	Path        string
	ExplicitURL bool
}

type Attempt struct {
	Target  string
	OK      bool
	Latency time.Duration
	Err     string
	Detail  string
}

type LayerResult struct {
	Name       string
	Status     string
	Confidence int
	Summary    string
	Attempts   []Attempt
}

type Diagnosis struct {
	Target     Target
	Overall    Verdict
	RootCause  string
	Confidence int
	Summary    string
	Evidence   []string
	Layers     []LayerResult
}

type Options struct {
	Timeout time.Duration
}

func Check(ctx context.Context, raw string, opts Options) (*Diagnosis, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	target, err := ParseTarget(raw)
	if err != nil {
		return nil, err
	}

	d := &Diagnosis{Target: target, Overall: VerdictInconclusive, RootCause: "unknown", Confidence: 20}

	dnsLayer, systemIPs, controlIPs := checkDNS(ctx, target.Host, opts.Timeout)
	d.Layers = append(d.Layers, dnsLayer)

	testIPs := limitIPs(preferredIPs(controlIPs, systemIPs), maxTestIPs)
	if len(testIPs) == 0 {
		d.Overall = VerdictAbnormal
		d.RootCause = "DNS failure"
		d.Confidence = 80
		d.Summary = "No usable A/AAAA records were resolved."
		d.Evidence = append(d.Evidence, dnsLayer.Summary)
		return d, nil
	}

	tcpLayer := checkTCP(ctx, testIPs, target.Port, opts.Timeout)
	d.Layers = append(d.Layers, tcpLayer)

	tlsLayer := LayerResult{Name: "TLS/SNI", Status: "skipped", Summary: "Target scheme does not require TLS."}
	if target.Port == "443" {
		tlsLayer = checkTLS(ctx, target.Host, testIPs, target.Port, opts.Timeout)
		d.Layers = append(d.Layers, tlsLayer)
	}

	httpLayer := checkHTTP(ctx, target, testIPs, opts.Timeout)
	d.Layers = append(d.Layers, httpLayer)
	if httpLayer.Status != "ok" && !target.ExplicitURL && target.Scheme == "https" {
		fallbackTarget := target
		fallbackTarget.Scheme = "http"
		fallbackTarget.Port = "80"
		tcp80Layer := checkTCP(ctx, testIPs, fallbackTarget.Port, opts.Timeout)
		tcp80Layer.Name = "TCP HTTP fallback"
		d.Layers = append(d.Layers, tcp80Layer)
		fallbackHTTP := checkHTTP(ctx, fallbackTarget, testIPs, opts.Timeout)
		fallbackHTTP.Name = "HTTP fallback"
		d.Layers = append(d.Layers, fallbackHTTP)
		if fallbackHTTP.Status == "ok" {
			httpLayer = fallbackHTTP
		}
	}

	quicLayer := LayerResult{Name: "HTTP/3 QUIC/SNI", Status: "skipped", Summary: "QUIC is only checked for HTTPS targets."}
	if target.Port == "443" {
		quicLayer = checkQUIC(ctx, target.Host, testIPs, opts.Timeout)
		d.Layers = append(d.Layers, quicLayer)
	}

	classify(d, dnsLayer, tcpLayer, tlsLayer, httpLayer, quicLayer)
	return d, nil
}

func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, errors.New("empty -G target")
	}

	explicit := strings.Contains(raw, "://")
	parseRaw := raw
	if !explicit {
		parseRaw = "https://" + raw
	}
	u, err := url.Parse(parseRaw)
	if err != nil || u.Host == "" {
		return Target{}, fmt.Errorf("invalid -G target: %s", raw)
	}

	host := u.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("invalid -G host: %s", raw)
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return Target{
		Raw: raw, Scheme: u.Scheme, Host: normalizeHost(host), Port: port, Path: path, ExplicitURL: explicit,
	}, nil
}

func checkDNS(ctx context.Context, host string, timeout time.Duration) (LayerResult, []string, []string) {
	layer := LayerResult{Name: "DNS", Status: "ok", Confidence: 40}
	var systemIPs, controlIPs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < attemptsPerCheck; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			rctx, cancel := context.WithTimeout(ctx, timeout)
			ips, err := net.DefaultResolver.LookupIP(rctx, "ip", host)
			cancel()
			at := Attempt{Target: "system resolver", Latency: time.Since(start)}
			var got []string
			if err != nil {
				at.Err = err.Error()
			} else {
				got = ipStrings(ips)
				at.OK = len(got) > 0
				at.Detail = strings.Join(got, ", ")
			}
			mu.Lock()
			systemIPs = append(systemIPs, got...)
			layer.Attempts = append(layer.Attempts, at)
			mu.Unlock()
		}()
	}

	for _, resolver := range []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"} {
		wg.Add(1)
		go func(resolver string) {
			defer wg.Done()
			ips, attempts := queryResolverBoth(ctx, resolver, host, timeout)
			mu.Lock()
			controlIPs = append(controlIPs, ips...)
			layer.Attempts = append(layer.Attempts, attempts...)
			mu.Unlock()
		}(resolver)
	}
	for _, endpoint := range []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"} {
		wg.Add(1)
		go func(endpoint string) {
			defer wg.Done()
			ips, attempts := queryDoHBoth(ctx, endpoint, host, timeout)
			mu.Lock()
			controlIPs = append(controlIPs, ips...)
			layer.Attempts = append(layer.Attempts, attempts...)
			mu.Unlock()
		}(endpoint)
	}
	wg.Wait()

	systemIPs = uniqueSorted(systemIPs)
	controlIPs = uniqueSorted(controlIPs)
	if len(systemIPs) == 0 && len(controlIPs) == 0 {
		layer.Status = "fail"
		layer.Confidence = 90
		layer.Summary = "All DNS resolvers failed."
		return layer, systemIPs, controlIPs
	}
	if len(systemIPs) > 0 && len(controlIPs) > 0 && !hasIntersection(systemIPs, controlIPs) {
		layer.Status = "anomaly"
		layer.Confidence = 80
		layer.Summary = fmt.Sprintf("System DNS differs from control DNS. system=[%s], control=[%s]", strings.Join(systemIPs, ", "), strings.Join(controlIPs, ", "))
		return layer, systemIPs, controlIPs
	}
	if hasBogon(systemIPs) && !hasBogon(controlIPs) && len(controlIPs) > 0 {
		layer.Status = "anomaly"
		layer.Confidence = 85
		layer.Summary = fmt.Sprintf("System DNS returned private/reserved IPs while control DNS did not. system=[%s]", strings.Join(systemIPs, ", "))
		return layer, systemIPs, controlIPs
	}
	layer.Summary = fmt.Sprintf("Resolved IPs: %s", strings.Join(preferredIPs(controlIPs, systemIPs), ", "))
	return layer, systemIPs, controlIPs
}

func checkTCP(ctx context.Context, ips []string, port string, timeout time.Duration) LayerResult {
	layer := LayerResult{Name: "TCP", Status: "fail", Confidence: 60}
	successes := 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		for i := 0; i < attemptsPerCheck; i++ {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				start := time.Now()
				d := net.Dialer{Timeout: timeout}
				cctx, cancel := context.WithTimeout(ctx, timeout)
				conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip, port))
				cancel()
				at := Attempt{Target: net.JoinHostPort(ip, port), Latency: time.Since(start)}
				if err != nil {
					at.Err = classifyNetErr(err)
				} else {
					at.OK = true
					conn.Close()
				}
				mu.Lock()
				if at.OK {
					successes++
				}
				layer.Attempts = append(layer.Attempts, at)
				mu.Unlock()
			}(ip)
		}
	}
	wg.Wait()
	if successes > 0 {
		layer.Status = "ok"
		layer.Confidence = 80
		layer.Summary = fmt.Sprintf("TCP connected in %d/%d attempts.", successes, len(layer.Attempts))
	} else {
		layer.Summary = fmt.Sprintf("TCP failed in all %d attempts.", len(layer.Attempts))
	}
	return layer
}

func checkTLS(ctx context.Context, host string, ips []string, port string, timeout time.Duration) LayerResult {
	layer := LayerResult{Name: "TLS/SNI", Status: "fail", Confidence: 60}
	normalOK, noSNIOK, wrongSNIOK := 0, 0, 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wrong := "example.com"
		if strings.EqualFold(host, wrong) {
			wrong = "iana.org"
		}
		for _, spec := range []struct {
			label string
			sni   string
			kind  string
		}{
			{"SNI=" + host, host, "normal"},
			{"no SNI", "", "nosni"},
			{"SNI=" + wrong, wrong, "wrong"},
		} {
			for i := 0; i < attemptsPerCheck; i++ {
				wg.Add(1)
				go func(ip, label, sni, kind string) {
					defer wg.Done()
					at := tlsAttempt(ctx, label, ip, port, sni, timeout)
					mu.Lock()
					if at.OK {
						switch kind {
						case "normal":
							normalOK++
						case "nosni":
							noSNIOK++
						case "wrong":
							wrongSNIOK++
						}
					}
					layer.Attempts = append(layer.Attempts, at)
					mu.Unlock()
				}(ip, spec.label, spec.sni, spec.kind)
			}
		}
	}
	wg.Wait()
	switch {
	case normalOK > 0:
		layer.Status = "ok"
		layer.Confidence = 85
		layer.Summary = fmt.Sprintf("TLS succeeded with target SNI in %d attempts.", normalOK)
	case normalOK == 0 && (noSNIOK > 0 || wrongSNIOK > 0):
		layer.Status = "anomaly"
		layer.Confidence = 85
		layer.Summary = "TLS failed only with the target SNI, consistent with SNI filtering."
	default:
		layer.Summary = "TLS failed for target and control SNI variants."
	}
	return layer
}

func tlsAttempt(ctx context.Context, label, ip, port, sni string, timeout time.Duration) Attempt {
	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: []string{"h2", "http/1.1"}}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	td := tls.Dialer{NetDialer: dialer, Config: conf}
	conn, err := td.DialContext(cctx, "tcp", net.JoinHostPort(ip, port))
	at := Attempt{Target: label + " -> " + net.JoinHostPort(ip, port), Latency: time.Since(start)}
	if err != nil {
		at.Err = classifyNetErr(err)
		return at
	}
	at.OK = true
	tlsConn := conn.(*tls.Conn)
	at.Detail = tls.VersionName(tlsConn.ConnectionState().Version)
	conn.Close()
	return at
}

func checkHTTP(ctx context.Context, target Target, ips []string, timeout time.Duration) LayerResult {
	layer := LayerResult{Name: "HTTP", Status: "fail", Confidence: 60}
	normalOK, hostControlOK := 0, 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		for i := 0; i < attemptsPerCheck; i++ {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				at := httpAttempt(ctx, target, ip, target.Host, timeout)
				mu.Lock()
				if at.OK {
					normalOK++
				}
				layer.Attempts = append(layer.Attempts, at)
				mu.Unlock()
			}(ip)
		}
		if target.Scheme == "http" {
			wrongHost := "example.com"
			if strings.EqualFold(target.Host, wrongHost) {
				wrongHost = "iana.org"
			}
			for i := 0; i < attemptsPerCheck; i++ {
				wg.Add(1)
				go func(ip, wrongHost string) {
					defer wg.Done()
					at := httpAttempt(ctx, target, ip, wrongHost, timeout)
					at.Target = "Host=" + wrongHost + " -> " + at.Target
					mu.Lock()
					if at.OK {
						hostControlOK++
					}
					layer.Attempts = append(layer.Attempts, at)
					mu.Unlock()
				}(ip, wrongHost)
			}
		}
	}
	wg.Wait()
	switch {
	case normalOK > 0:
		layer.Status = "ok"
		layer.Confidence = 90
		layer.Summary = fmt.Sprintf("HTTP request succeeded in %d attempts.", normalOK)
	case target.Scheme == "http" && normalOK == 0 && hostControlOK > 0:
		layer.Status = "anomaly"
		layer.Confidence = 80
		layer.Summary = "HTTP failed with target Host but succeeded with a control Host, consistent with Host filtering."
	default:
		layer.Summary = "HTTP request failed for all target attempts."
	}
	return layer
}

func httpAttempt(ctx context.Context, target Target, ip, hostHeader string, timeout time.Duration) Attempt {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         target.Host,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, net.JoinHostPort(ip, target.Port))
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	u := target.Scheme + "://" + hostForURL(target.Host)
	if (target.Scheme == "http" && target.Port != "80") || (target.Scheme == "https" && target.Port != "443") {
		u += ":" + target.Port
	}
	u += target.Path
	req, err := http.NewRequestWithContext(cctx, "GET", u, nil)
	if err != nil {
		return Attempt{Target: u, Latency: time.Since(start), Err: err.Error()}
	}
	req.Host = hostHeader
	resp, err := client.Do(req)
	at := Attempt{Target: target.Scheme + "://" + hostHeader + " via " + net.JoinHostPort(ip, target.Port), Latency: time.Since(start)}
	if err != nil {
		at.Err = classifyNetErr(err)
		return at
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	at.OK = resp.StatusCode >= 200 && resp.StatusCode < 500
	at.Detail = fmt.Sprintf("status=%d proto=%s body_sha256=%x", resp.StatusCode, resp.Proto, sha256Bytes(body)[:6])
	return at
}

func checkQUIC(ctx context.Context, host string, ips []string, timeout time.Duration) LayerResult {
	layer := LayerResult{Name: "HTTP/3 QUIC/SNI", Status: "fail", Confidence: 50}
	normalOK, controlOK := 0, 0
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wrong := "example.com"
		if strings.EqualFold(host, wrong) {
			wrong = "iana.org"
		}
		for _, spec := range []struct {
			label string
			sni   string
			kind  string
		}{
			{"SNI=" + host, host, "normal"},
			{"SNI=" + wrong, wrong, "control"},
		} {
			for i := 0; i < attemptsPerCheck; i++ {
				wg.Add(1)
				go func(ip, label, sni, kind string) {
					defer wg.Done()
					at := quicAttempt(ctx, label, ip, sni, timeout)
					mu.Lock()
					if at.OK {
						if kind == "normal" {
							normalOK++
						} else {
							controlOK++
						}
					}
					layer.Attempts = append(layer.Attempts, at)
					mu.Unlock()
				}(ip, spec.label, spec.sni, spec.kind)
			}
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			at := randomUDPProbe(ctx, ip, timeout)
			mu.Lock()
			layer.Attempts = append(layer.Attempts, at)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	if normalOK > 0 {
		layer.Status = "ok"
		layer.Confidence = 85
		layer.Summary = fmt.Sprintf("QUIC connected with target SNI in %d attempts.", normalOK)
	} else if controlOK > 0 {
		layer.Status = "anomaly"
		layer.Confidence = 75
		layer.Summary = "QUIC failed with target SNI but a control SNI connected, consistent with QUIC SNI filtering."
	} else {
		layer.Summary = "QUIC did not connect. This may be normal if the site does not support HTTP/3."
	}
	return layer
}

func quicAttempt(ctx context.Context, label, ip, sni string, timeout time.Duration) Attempt {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := quic.DialAddr(cctx, net.JoinHostPort(ip, "443"), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		NextProtos:         []string{"h3"},
	}, &quic.Config{MaxIdleTimeout: timeout})
	at := Attempt{Target: label + " -> " + net.JoinHostPort(ip, "443"), Latency: time.Since(start)}
	if err != nil {
		at.Err = classifyNetErr(err)
		return at
	}
	at.OK = true
	at.Detail = "QUIC connected"
	conn.CloseWithError(0, "")
	return at
}

func randomUDPProbe(ctx context.Context, ip string, timeout time.Duration) Attempt {
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	conn, err := d.DialContext(cctx, "udp", net.JoinHostPort(ip, "443"))
	cancel()
	at := Attempt{Target: "random UDP -> " + net.JoinHostPort(ip, "443"), Latency: time.Since(start)}
	if err != nil {
		at.Err = classifyNetErr(err)
		return at
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write([]byte("IPORT-G-UDP-CONTROL"))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	at.Latency = time.Since(start)
	if err != nil {
		at.Err = classifyNetErr(err)
	} else {
		at.OK = true
		at.Detail = "received UDP response"
	}
	_ = ctx
	return at
}

func classify(d *Diagnosis, dns, tcp, tlsLayer, httpLayer, quic LayerResult) {
	switch {
	case httpLayer.Status == "ok":
		d.Overall = VerdictNormal
		d.RootCause = "none"
		d.Confidence = 90
		d.Summary = "Website is reachable from this network."
	case dns.Status == "anomaly":
		d.Overall = VerdictLikelyGFW
		d.RootCause = "DNS poisoning"
		d.Confidence = dns.Confidence
		d.Summary = "DNS answers differ from control resolvers or look forged."
		d.Evidence = append(d.Evidence, dns.Summary)
	case tcp.Status == "fail":
		d.Overall = VerdictAbnormal
		d.RootCause = "TCP/IP blocking or origin unreachable"
		d.Confidence = 65
		d.Summary = "Resolved IPs could not be reached at the TCP layer."
		d.Evidence = append(d.Evidence, tcp.Summary)
	case tlsLayer.Status == "anomaly":
		d.Overall = VerdictLikelyGFW
		d.RootCause = "TLS SNI blocking"
		d.Confidence = tlsLayer.Confidence
		d.Summary = "TLS failures depend on the target SNI."
		d.Evidence = append(d.Evidence, tlsLayer.Summary)
	case httpLayer.Status == "anomaly":
		d.Overall = VerdictLikelyGFW
		d.RootCause = "HTTP Host blocking"
		d.Confidence = httpLayer.Confidence
		d.Summary = "HTTP behavior differs when the Host header changes."
		d.Evidence = append(d.Evidence, httpLayer.Summary)
	case quic.Status == "anomaly":
		d.Overall = VerdictLikelyGFW
		d.RootCause = "QUIC SNI blocking"
		d.Confidence = quic.Confidence
		d.Summary = "QUIC failures depend on target SNI."
		d.Evidence = append(d.Evidence, quic.Summary)
	default:
		d.Overall = VerdictAbnormal
		d.RootCause = "origin down or local network failure"
		d.Confidence = 50
		d.Summary = "The site was not reachable, but no censorship-specific signature was isolated."
	}
}

func queryResolverBoth(ctx context.Context, resolver, host string, timeout time.Duration) ([]string, []Attempt) {
	var ips []string
	var attempts []Attempt
	for _, network := range []string{"udp", "tcp"} {
		for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			got, at := queryDNS(ctx, network, resolver, host, qtype, timeout)
			ips = append(ips, got...)
			attempts = append(attempts, at)
		}
	}
	return uniqueSorted(ips), attempts
}

func queryDNS(ctx context.Context, network, resolver, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, Attempt) {
	start := time.Now()
	msg, err := dnsQueryMessage(host, qtype)
	at := Attempt{Target: fmt.Sprintf("%s %s %s", network, resolver, qtype), Latency: 0}
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(cctx, network, resolver)
	if err != nil {
		at.Latency = time.Since(start)
		at.Err = classifyNetErr(err)
		return nil, at
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if network == "tcp" {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(msg)))
		if _, err = conn.Write(append(prefix[:], msg...)); err != nil {
			at.Latency = time.Since(start)
			at.Err = classifyNetErr(err)
			return nil, at
		}
		if _, err = io.ReadFull(conn, prefix[:]); err != nil {
			at.Latency = time.Since(start)
			at.Err = classifyNetErr(err)
			return nil, at
		}
		resp := make([]byte, binary.BigEndian.Uint16(prefix[:]))
		_, err = io.ReadFull(conn, resp)
		msg = resp
	} else {
		if _, err = conn.Write(msg); err != nil {
			at.Latency = time.Since(start)
			at.Err = classifyNetErr(err)
			return nil, at
		}
		resp := make([]byte, 1500)
		n, readErr := conn.Read(resp)
		err = readErr
		msg = resp[:n]
	}
	at.Latency = time.Since(start)
	if err != nil {
		at.Err = classifyNetErr(err)
		return nil, at
	}
	ips, err := parseDNSResponse(msg)
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	at.OK = len(ips) > 0
	at.Detail = strings.Join(ips, ", ")
	return ips, at
}

func queryDoHBoth(ctx context.Context, endpoint, host string, timeout time.Duration) ([]string, []Attempt) {
	var ips []string
	var attempts []Attempt
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		got, at := queryDoH(ctx, endpoint, host, qtype, timeout)
		ips = append(ips, got...)
		attempts = append(attempts, at)
	}
	return uniqueSorted(ips), attempts
}

func queryDoH(ctx context.Context, endpoint, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, Attempt) {
	start := time.Now()
	msg, err := dnsQueryMessage(host, qtype)
	at := Attempt{Target: fmt.Sprintf("DoH %s %s", endpoint, qtype)}
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "POST", endpoint, bytes.NewReader(msg))
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	at.Latency = time.Since(start)
	if err != nil {
		at.Err = classifyNetErr(err)
		return nil, at
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	if resp.StatusCode != http.StatusOK {
		at.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return nil, at
	}
	ips, err := parseDNSResponse(body)
	if err != nil {
		at.Err = err.Error()
		return nil, at
	}
	at.OK = len(ips) > 0
	at.Detail = strings.Join(ips, ", ")
	return ips, at
}

func dnsQueryMessage(host string, qtype dnsmessage.Type) ([]byte, error) {
	id, _ := rand.Int(rand.Reader, big.NewInt(65535))
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(id.Int64()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name: name, Type: qtype, Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

func parseDNSResponse(msg []byte) ([]string, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return nil, err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var ips []string
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, net.IP(a.A[:]).String())
		case dnsmessage.TypeAAAA:
			aaaa, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			ips = append(ips, net.IP(aaaa.AAAA[:]).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	return uniqueSorted(ips), nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func uniqueSorted(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || m[s] {
			continue
		}
		m[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func preferredIPs(control, system []string) []string {
	if len(control) > 0 {
		return control
	}
	return system
}

func limitIPs(ips []string, n int) []string {
	if len(ips) <= n {
		return ips
	}
	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	ordered := append(v4, v6...)
	if len(ordered) > n {
		ordered = ordered[:n]
	}
	return ordered
}

func hasIntersection(a, b []string) bool {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if m[s] {
			return true
		}
	}
	return false
}

func hasBogon(ips []string) bool {
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err == nil && (addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified()) {
			return true
		}
	}
	return false
}

func normalizeHost(host string) string {
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.Index(host, "%25"); i != -1 {
		host = host[:i]
	}
	if i := strings.Index(host, "%"); i != -1 {
		host = host[:i]
	}
	return host
}

func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func classifyNetErr(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "reset"):
		return "connection reset"
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "timeout/drop"
	case strings.Contains(s, "no such host"):
		return "no such host"
	default:
		return err.Error()
	}
}

func DoHGetURL(endpoint, host string, qtype dnsmessage.Type) (string, error) {
	msg, err := dnsQueryMessage(host, qtype)
	if err != nil {
		return "", err
	}
	return endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(msg), nil
}
