package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yiwei/iport/internal/scanner"
	"github.com/yiwei/iport/internal/ui"
)

func main() {
	var target string
	var ports string
	var timeoutMs int

	flag.StringVar(&target, "t", "", "Target IP or domain (e.g., example.com, 192.168.1.1)")
	flag.StringVar(&ports, "p", "80,443", "Ports to scan (comma separated)")
	flag.IntVar(&timeoutMs, "timeout", 2000, "Timeout in milliseconds for each probe")
	flag.Parse()

	// If target is not provided via flag, check positional argument
	if target == "" {
		args := flag.Args()
		if len(args) > 0 {
			target = args[0]
		}
	}

	if target == "" {
		fmt.Println("Usage: iport <target> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	portList := strings.Split(ports, ",")
	timeout := time.Duration(timeoutMs) * time.Millisecond

	ui.PrintHeader(target)

	var wg sync.WaitGroup

	// Phase 1: Basic Connectivity (ICMP, TCP)
	ui.PrintSection("L3/L4 Basic Connectivity")

	// ICMP
	wg.Add(1)
	go func() {
		defer wg.Done()
		err, rtt := scanner.Ping(target, timeout)
		ui.PrintResult("ICMP Ping", err, fmt.Sprintf("RTT: %v", rtt))
	}()

	// TCP Ports
	for _, p := range portList {
		wg.Add(1)
		port := strings.TrimSpace(p)
		go func(port string) {
			defer wg.Done()
			err := scanner.CheckTCP(target, port, timeout)
			ui.PrintResult(fmt.Sprintf("TCP Port %s", port), err, "Open")
		}(port)
	}

	wg.Wait()

	// Phase 2: TLS Detection (only on 443 for now)
	has443 := false
	for _, p := range portList {
		if strings.TrimSpace(p) == "443" {
			has443 = true
			break
		}
	}

	if has443 {
		ui.PrintSection("TLS Detection (Port 443)")
		tlsVersions := []uint16{
			scanner.VersionTLS10,
			scanner.VersionTLS11,
			scanner.VersionTLS12,
			scanner.VersionTLS13,
		}

		for _, v := range tlsVersions {
			wg.Add(1)
			go func(version uint16) {
				defer wg.Done()
				err, cipher := scanner.CheckTLS(target, "443", version, timeout)
				name := scanner.TLSVersionName(version)

				if err == nil {
					ui.PrintResult(fmt.Sprintf("TLS %s", name), nil, fmt.Sprintf("Supported (Cipher: %s)", cipher))
				} else {
					ui.PrintResult(fmt.Sprintf("TLS %s", name), err, "")
				}
			}(v)
		}
		wg.Wait()

		// Phase 3: Application Layer (HTTP/1, H2, H3)
		ui.PrintSection("Application Layer (L7)")

		// HTTP/1 & H2
		wg.Add(1)
		go func() {
			defer wg.Done()
			err, proto := scanner.CheckHTTP(target, timeout)
			if err == nil {
				ui.PrintResult("HTTP (over TCP)", nil, fmt.Sprintf("Negotiated: %s", proto))
			} else {
				ui.PrintResult("HTTP (over TCP)", err, "")
			}
		}()

		// HTTP/3 (QUIC)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := scanner.CheckHTTP3(target, "443", timeout)
			if err == nil {
				ui.PrintResult("HTTP/3 (QUIC/UDP)", nil, "Supported")
			} else {
				ui.PrintResult("HTTP/3 (QUIC/UDP)", err, "")
			}
		}()

		wg.Wait()
	}

	fmt.Println()
}
