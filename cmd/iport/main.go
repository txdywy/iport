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

var Version = "dev"

// ScanResult is the decoupled result type — scanner produces, UI consumes.
type ScanResult struct {
	Kind        string // "section", "result", "proxy", "proxy-summary", "progress", "clear-progress"
	Name        string
	Err         error
	Extra       string
	Port        string
	Probes      []ui.ProbeDisplay
	AllProbes   map[string][]ui.ProbeDisplay
	Total, Done int
}

func main() {
	// Workaround for Go's flag package stopping on the first non-flag argument.
	if len(os.Args) > 2 && !strings.HasPrefix(os.Args[1], "-") {
		arg := os.Args[1]
		os.Args = append(os.Args[:1], os.Args[2:]...)
		os.Args = append(os.Args, arg)
	}

	var (
		target      string
		ports       string
		timeoutMs   int
		showVersion bool
		allPorts    bool
		tcpOnly     bool
		udpScan     bool
		concurrency int
		probeProxy  bool
		probeOnly   bool
		listProbes  bool
	)

	flag.StringVar(&target, "t", "", "Target IP or domain")
	flag.StringVar(&ports, "p", "", "Ports to scan (comma separated, default: 80,443)")
	flag.IntVar(&timeoutMs, "timeout", 2000, "Timeout in milliseconds")
	flag.BoolVar(&showVersion, "V", false, "Show version and exit")
	flag.BoolVar(&allPorts, "A", false, "Scan all 65535 ports (TCP+UDP, equivalent to -T -U)")
	flag.BoolVar(&tcpOnly, "T", false, "Enable TCP scanning")
	flag.BoolVar(&udpScan, "U", false, "Enable UDP scanning")
	flag.IntVar(&concurrency, "c", 1000, "Maximum concurrent scans")
	flag.BoolVar(&probeProxy, "probe", true, "Enable proxy protocol detection")
	flag.BoolVar(&probeOnly, "probe-only", false, "Skip TLS/HTTP, only run proxy probes")
	flag.BoolVar(&listProbes, "list-probes", false, "List supported protocols and exit")
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

	// Normalize IPv6: strip brackets/zone for dial, keep clean for display
	target = scanner.NormalizeHost(target)

	// Validate concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	// Initialize global concurrency semaphore
	scanner.SetSemaphore(concurrency)

	var portList []string
	if allPorts {
		portList = make([]string, 65535)
		for i := range portList {
			portList[i] = strconv.Itoa(i + 1)
		}
		if !probeOnly {
			probeProxy = false
		}
	} else {
		if ports == "" {
			ports = "80,443"
		}
		portList = parseAndValidatePorts(ports)
		if len(portList) == 0 {
			fmt.Println("Error: no valid ports specified. Ports must be integers 1-65535.")
			os.Exit(1)
		}
	}

	// Scan mode:
	// -T = TCP, -U = UDP, -T -U = both, -A = all ports TCP+UDP
	// No -T/-U/-A = default TCP+UDP on specified ports
	scanTCP := true
	scanUDP := true
	if tcpOnly || udpScan {
		// Explicit mode: only scan what's requested
		scanTCP = tcpOnly
		scanUDP = udpScan
	}
	if allPorts {
		// -A = all ports, implies both TCP+UDP
		scanTCP = true
		scanUDP = true
		// But respect -T/-U if explicitly given with -A
		if tcpOnly && !udpScan {
			scanUDP = false
		}
		if udpScan && !tcpOnly {
			scanTCP = false
		}
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	bigScan := len(portList) > 100

	// --- Result channel: scanner goroutines produce, UI goroutine consumes ---
	results := make(chan ScanResult, 256)
	var uiDone sync.WaitGroup
	uiDone.Add(1)
	go func() {
		defer uiDone.Done()
		for r := range results {
			switch r.Kind {
			case "section":
				ui.PrintSection(r.Name)
			case "result":
				ui.PrintResult(r.Name, r.Err, r.Extra)
			case "proxy":
				ui.PrintProxyResults(r.Port, r.Probes)
			case "proxy-summary":
				ui.PrintProxySummary(r.AllProbes)
			case "progress":
				ui.PrintProgress(r.Total, r.Done)
			case "clear-progress":
				ui.ClearProgress()
			}
		}
	}()

	emit := func(r ScanResult) { results <- r }

	// emitBatch sends multiple results atomically — no interleaving from other goroutines.
	var emitMu sync.Mutex
	emitBatch := func(batch []ScanResult) {
		emitMu.Lock()
		defer emitMu.Unlock()
		for _, r := range batch {
			results <- r
		}
	}

	ui.PrintHeader(target)

	// ========== Phase 1: Basic Connectivity ==========
	emit(ScanResult{Kind: "section", Name: "L3/L4 Basic Connectivity"})

	var wg sync.WaitGroup

	// ICMP
	wg.Add(1)
	go func() {
		defer wg.Done()
		rtt, err := scanner.Ping(target, timeout)
		emit(ScanResult{Kind: "result", Name: "ICMP Ping", Err: err, Extra: fmt.Sprintf("RTT: %v", rtt)})
	}()

	// TCP/UDP port scanning
	var openTCPPorts, openUDPPorts []string
	var portsMu sync.Mutex

	type portJob struct{ port string }
	jobs := make(chan portJob, concurrency)
	var scannedPorts int32
	var doneCh chan struct{}
	var progressWG sync.WaitGroup

	if bigScan {
		doneCh = make(chan struct{})
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			total := len(portList)
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					emit(ScanResult{Kind: "progress", Total: total, Done: int(atomic.LoadInt32(&scannedPorts))})
				case <-doneCh:
					emit(ScanResult{Kind: "clear-progress"})
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
				if scanTCP {
					if err := scanner.CheckTCP(target, port, timeout); err == nil {
						portsMu.Lock()
						openTCPPorts = append(openTCPPorts, port)
						portsMu.Unlock()
						if bigScan {
							emit(ScanResult{Kind: "clear-progress"})
						}
						emit(ScanResult{Kind: "result", Name: fmt.Sprintf("TCP Port %s", port), Extra: "Open"})
					} else if !bigScan {
						emit(ScanResult{Kind: "result", Name: fmt.Sprintf("TCP Port %s", port), Err: err})
					}
				}

				if scanUDP {
					udpErr := scanner.CheckUDP(target, port, timeout)
					if udpErr != nil && strings.Contains(udpErr.Error(), "timeout") {
						// open|filtered — candidate for UDP proxy probes
						portsMu.Lock()
						openUDPPorts = append(openUDPPorts, port)
						portsMu.Unlock()
						if !bigScan {
							emit(ScanResult{Kind: "result", Name: fmt.Sprintf("UDP Port %s", port), Err: fmt.Errorf("timeout (open|filtered)")})
						}
					} else if udpErr == nil {
						portsMu.Lock()
						openUDPPorts = append(openUDPPorts, port)
						portsMu.Unlock()
						if bigScan {
							emit(ScanResult{Kind: "clear-progress"})
						}
						emit(ScanResult{Kind: "result", Name: fmt.Sprintf("UDP Port %s", port), Extra: "Open"})
					} else if !bigScan {
						emit(ScanResult{Kind: "result", Name: fmt.Sprintf("UDP Port %s", port), Err: udpErr})
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
		progressWG.Wait()
	}

	sort.Slice(openTCPPorts, func(i, j int) bool {
		a, _ := strconv.Atoi(openTCPPorts[i])
		b, _ := strconv.Atoi(openTCPPorts[j])
		return a < b
	})
	sort.Slice(openUDPPorts, func(i, j int) bool {
		a, _ := strconv.Atoi(openUDPPorts[i])
		b, _ := strconv.Atoi(openUDPPorts[j])
		return a < b
	})

	// ========== Phase 2 & 3: TLS + Application Layer ==========
	if !probeOnly {
		for _, port := range openTCPPorts {
			wg.Add(1)
			go func(port string) {
				defer wg.Done()

				// Collect all results for this port, then emit as batch
				var batch []ScanResult
				batch = append(batch, ScanResult{Kind: "section", Name: fmt.Sprintf("TLS Detection (Port %s)", port)})

				var tlsResults []ScanResult
				var tlsMu sync.Mutex
				var tlsWG sync.WaitGroup
				for _, v := range []uint16{scanner.VersionTLS10, scanner.VersionTLS11, scanner.VersionTLS12, scanner.VersionTLS13} {
					tlsWG.Add(1)
					go func(version uint16) {
						defer tlsWG.Done()
						cipher, err := scanner.CheckTLS(target, port, version, timeout)
						name := fmt.Sprintf("TLS %s", scanner.TLSVersionName(version))
						r := ScanResult{Kind: "result", Name: name, Err: err}
						if err == nil {
							r.Extra = fmt.Sprintf("Supported (Cipher: %s)", cipher)
						}
						tlsMu.Lock()
						tlsResults = append(tlsResults, r)
						tlsMu.Unlock()
					}(v)
				}
				tlsWG.Wait()
				batch = append(batch, tlsResults...)

				batch = append(batch, ScanResult{Kind: "section", Name: fmt.Sprintf("Application Layer (L7) (Port %s)", port)})

				var appResults []ScanResult
				var appMu sync.Mutex
				var appWG sync.WaitGroup
				appWG.Add(1)
				go func() {
					defer appWG.Done()
					proto, err := scanner.CheckHTTP(target, port, timeout)
					r := ScanResult{Kind: "result", Name: "HTTP (over TCP)", Err: err}
					if err == nil {
						r.Extra = fmt.Sprintf("Negotiated: %s", proto)
					}
					appMu.Lock()
					appResults = append(appResults, r)
					appMu.Unlock()
				}()
				if scanUDP {
					appWG.Add(1)
					go func() {
						defer appWG.Done()
						err := scanner.CheckHTTP3(target, port, timeout)
						r := ScanResult{Kind: "result", Name: "HTTP/3 (QUIC/UDP)", Err: err}
						if err == nil {
							r.Extra = "Supported"
						}
						appMu.Lock()
						appResults = append(appResults, r)
						appMu.Unlock()
					}()
				}
				appWG.Wait()
				batch = append(batch, appResults...)

				// Emit entire port batch atomically
				emitBatch(batch)
			}(port)
		}
		wg.Wait()
	}

	// ========== Phase 4: Proxy Protocol Detection ==========
	if probeProxy || probeOnly {
		allProxyResults := make(map[string][]ui.ProbeDisplay)
		var proxyMu sync.Mutex

		for _, port := range openTCPPorts {
			wg.Add(1)
			go func(port string) {
				defer wg.Done()
				displays := toDisplays(scanner.RunTCPProbes(target, port, timeout))
				emitBatch([]ScanResult{
					{Kind: "section", Name: fmt.Sprintf("Proxy Protocol Detection (TCP Port %s)", port)},
					{Kind: "proxy", Port: port, Probes: displays},
				})
				if len(displays) > 0 {
					proxyMu.Lock()
					allProxyResults[port] = displays
					proxyMu.Unlock()
				}
			}(port)
		}

		for _, port := range openUDPPorts {
			wg.Add(1)
			go func(port string) {
				defer wg.Done()
				displays := toDisplays(scanner.RunUDPProbes(target, port, timeout))
				emitBatch([]ScanResult{
					{Kind: "section", Name: fmt.Sprintf("Proxy Protocol Detection (UDP Port %s)", port)},
					{Kind: "proxy", Port: port, Probes: displays},
				})
				if len(displays) > 0 {
					proxyMu.Lock()
					allProxyResults["udp/"+port] = displays
					proxyMu.Unlock()
				}
			}(port)
		}

		wg.Wait()
		emit(ScanResult{Kind: "proxy-summary", AllProbes: allProxyResults})
	}

	close(results)
	uiDone.Wait()
	fmt.Println()
}

func toDisplays(results []scanner.ProbeResult) []ui.ProbeDisplay {
	out := make([]ui.ProbeDisplay, len(results))
	for i, r := range results {
		out[i] = ui.ProbeDisplay{Protocol: r.Protocol, Transport: r.Transport, Confidence: r.Confidence}
	}
	return out
}

func parseAndValidatePorts(ports string) []string {
	seen := map[int]bool{}
	var valid []string
	for _, s := range strings.Split(ports, ",") {
		s = strings.TrimSpace(s)
		p, err := strconv.Atoi(s)
		if err != nil || p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		valid = append(valid, strconv.Itoa(p))
	}
	return valid
}
