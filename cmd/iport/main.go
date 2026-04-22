package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/txdywy/iport/internal/scanner"
	"github.com/txdywy/iport/internal/ui"
)

var (
	Version = "dev"
)

func main() {
	// Workaround for Go's flag package stopping on the first non-flag argument.
	if len(os.Args) > 2 && !strings.HasPrefix(os.Args[1], "-") {
		arg := os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
		os.Args = append(os.Args, arg)
	}

	var target string
	var ports string
	var timeoutMs int
	var showVersion bool
	var allPorts bool
	var concurrency int
	var probeProxy bool
	var probeOnly bool
	var listProbes bool

	flag.StringVar(&target, "t", "", "Target IP or domain (e.g., example.com, 192.168.1.1)")
	flag.StringVar(&ports, "p", "", "Ports to scan (comma separated). If not provided, defaults to 80,443")
	flag.IntVar(&timeoutMs, "timeout", 2000, "Timeout in milliseconds for each probe")
	flag.BoolVar(&showVersion, "V", false, "Show version and exit")
	flag.BoolVar(&allPorts, "A", false, "Scan all 65535 TCP ports")
	flag.IntVar(&concurrency, "c", 1000, "Maximum concurrent port scans")
	flag.BoolVar(&probeProxy, "probe", true, "Enable proxy protocol detection on open ports")
	flag.BoolVar(&probeOnly, "probe-only", false, "Skip TLS/HTTP detection, only run proxy protocol probes")
	flag.BoolVar(&listProbes, "list-probes", false, "List all supported proxy protocol probes and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("iport version %s\n", Version)
		os.Exit(0)
	}

	if listProbes {
		ui.PrintProbeList(scanner.ListAllProbes())
		os.Exit(0)
	}

	if target == "" {
		if args := flag.Args(); len(args) > 0 {
			target = args[0]
		}
	}

	if target == "" {
		fmt.Println("Usage: iport <target> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var portList []string
	if allPorts {
		portList = make([]string, 65535)
		for i := range portList {
			portList[i] = strconv.Itoa(i + 1)
		}
		if !probeOnly {
			probeProxy = false // disable probe for full port scan by default
		}
	} else {
		if ports == "" {
			ports = "80,443"
		}
		portList = strings.Split(ports, ",")
		for i := range portList {
			portList[i] = strings.TrimSpace(portList[i])
		}
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	bigScan := len(portList) > 100

	ui.PrintHeader(target)

	// Phase 1: Basic Connectivity
	ui.PrintSection("L3/L4 Basic Connectivity")

	var wg sync.WaitGroup

	// ICMP
	wg.Add(1)
	go func() {
		defer wg.Done()
		rtt, err := scanner.Ping(target, timeout)
		ui.PrintResult("ICMP Ping", err, fmt.Sprintf("RTT: %v", rtt))
	}()

	// TCP/UDP port scanning with worker pool
	var openTCPPorts []string
	var openUDPPorts []string
	var openPortsMu sync.Mutex

	type portJob struct{ port string }
	jobs := make(chan portJob, concurrency)

	var scannedPorts int32
	var doneCh chan struct{}

	if bigScan {
		doneCh = make(chan struct{})
		go func() {
			total := len(portList)
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					p := atomic.LoadInt32(&scannedPorts)
					ui.PrintProgress(total, int(p))
				case <-doneCh:
					ui.ClearProgress()
					return
				}
			}
		}()
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				port := job.port
				err := scanner.CheckTCP(target, port, timeout)
				if err == nil {
					openPortsMu.Lock()
					openTCPPorts = append(openTCPPorts, port)
					openPortsMu.Unlock()
					if bigScan {
						ui.ClearProgress()
					}
					ui.PrintResult(fmt.Sprintf("TCP Port %s", port), nil, "Open")
				} else if !bigScan {
					ui.PrintResult(fmt.Sprintf("TCP Port %s", port), err, "")
				}

				if !allPorts {
					udpErr := scanner.CheckUDP(target, port, timeout)
					if udpErr != nil && strings.Contains(udpErr.Error(), "timeout") {
						openPortsMu.Lock()
						openUDPPorts = append(openUDPPorts, port)
						openPortsMu.Unlock()
						if !bigScan {
							ui.PrintResult(fmt.Sprintf("UDP Port %s", port), fmt.Errorf("timeout (open|filtered)"), "")
						}
					} else if udpErr == nil {
						openPortsMu.Lock()
						openUDPPorts = append(openUDPPorts, port)
						openPortsMu.Unlock()
						if bigScan {
							ui.ClearProgress()
						}
						ui.PrintResult(fmt.Sprintf("UDP Port %s", port), nil, "Open")
					} else if !bigScan {
						ui.PrintResult(fmt.Sprintf("UDP Port %s", port), udpErr, "")
					}
				}

				atomic.AddInt32(&scannedPorts, 1)
			}
		}()
	}

	for _, p := range portList {
		jobs <- portJob{port: p}
	}
	close(jobs)

	wg.Wait()
	if doneCh != nil {
		close(doneCh)
	}

	sort.Strings(openTCPPorts)
	sort.Strings(openUDPPorts)

	// Phase 2 & 3: TLS Detection and Application Layer (skip if -probe-only)
	if !probeOnly {
		for _, port := range openTCPPorts {
			ui.PrintSection(fmt.Sprintf("TLS Detection (Port %s)", port))
			tlsVersions := []uint16{
				scanner.VersionTLS10,
				scanner.VersionTLS11,
				scanner.VersionTLS12,
				scanner.VersionTLS13,
			}

			for _, v := range tlsVersions {
				wg.Add(1)
				go func(version uint16, port string) {
					defer wg.Done()
					cipher, err := scanner.CheckTLS(target, port, version, timeout)
					name := scanner.TLSVersionName(version)
					if err == nil {
						ui.PrintResult(fmt.Sprintf("TLS %s", name), nil, fmt.Sprintf("Supported (Cipher: %s)", cipher))
					} else {
						ui.PrintResult(fmt.Sprintf("TLS %s", name), err, "")
					}
				}(v, port)
			}
			wg.Wait()

			ui.PrintSection(fmt.Sprintf("Application Layer (L7) (Port %s)", port))

			wg.Add(1)
			go func(port string) {
				defer wg.Done()
				proto, err := scanner.CheckHTTP(target, port, timeout)
				if err == nil {
					ui.PrintResult("HTTP (over TCP)", nil, fmt.Sprintf("Negotiated: %s", proto))
				} else {
					ui.PrintResult("HTTP (over TCP)", err, "")
				}
			}(port)

			wg.Add(1)
			go func(port string) {
				defer wg.Done()
				err := scanner.CheckHTTP3(target, port, timeout)
				if err == nil {
					ui.PrintResult("HTTP/3 (QUIC/UDP)", nil, "Supported")
				} else {
					ui.PrintResult("HTTP/3 (QUIC/UDP)", err, "")
				}
			}(port)

			wg.Wait()
		}
	}

	// Phase 4: Proxy Protocol Detection
	if probeProxy || probeOnly {
		allProxyResults := make(map[string][]ui.ProbeDisplay)

		// TCP probes on open TCP ports
		for _, port := range openTCPPorts {
			ui.PrintSection(fmt.Sprintf("Proxy Protocol Detection (TCP Port %s)", port))
			results := scanner.RunTCPProbes(target, port, timeout)
			displays := toDisplays(results)
			ui.PrintProxyResults(port, displays)
			if len(displays) > 0 {
				allProxyResults[port] = displays
			}
		}

		// UDP probes on open/filtered UDP ports
		for _, port := range openUDPPorts {
			ui.PrintSection(fmt.Sprintf("Proxy Protocol Detection (UDP Port %s)", port))
			results := scanner.RunUDPProbes(target, port, timeout)
			displays := toDisplays(results)
			ui.PrintProxyResults(port, displays)
			if len(displays) > 0 {
				allProxyResults["udp/"+port] = displays
			}
		}

		// Summary
		ui.PrintProxySummary(allProxyResults)
	}

	fmt.Println()
}

func toDisplays(results []scanner.ProbeResult) []ui.ProbeDisplay {
	out := make([]ui.ProbeDisplay, len(results))
	for i, r := range results {
		out[i] = ui.ProbeDisplay{
			Protocol:   r.Protocol,
			Transport:  r.Transport,
			Confidence: r.Confidence,
		}
	}
	return out
}
