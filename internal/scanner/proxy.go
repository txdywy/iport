package scanner

import (
	"context"
	"sync"
	"time"
)

// ProbeResult represents a detected proxy protocol with confidence scoring.
type ProbeResult struct {
	Protocol   string  // e.g. "VLESS", "Trojan", "Shadowsocks"
	Transport  string  // e.g. "TCP", "TLS", "WebSocket", "gRPC", "XHTTP", "Reality"
	Confidence float64 // 0-100
}

// ProbeFunc is the signature for all protocol probes.
type ProbeFunc func(host, port string, timeout time.Duration) []ProbeResult

// NamedProbe pairs a human-readable name with a probe function.
type NamedProbe struct {
	Name string
	Fn   ProbeFunc
}

// Probe registries — populated by init() in each probe_*.go file.
var (
	AllTCPProbes []NamedProbe
	AllUDPProbes []NamedProbe
)

// Max concurrent probes per port to prevent FD exhaustion.
const maxProbeParallel = 8

// RunTCPProbes runs all registered TCP probes with bounded concurrency and a total timeout budget.
func RunTCPProbes(host, port string, timeout time.Duration) []ProbeResult {
	return runProbes(AllTCPProbes, host, port, timeout)
}

// RunUDPProbes runs all registered UDP probes with bounded concurrency and a total timeout budget.
func RunUDPProbes(host, port string, timeout time.Duration) []ProbeResult {
	return runProbes(AllUDPProbes, host, port, timeout)
}

func runProbes(probes []NamedProbe, host, port string, timeout time.Duration) []ProbeResult {
	// Total budget: 3x single probe timeout, so we don't wait forever
	ctx, cancel := context.WithTimeout(context.Background(), timeout*3)
	defer cancel()

	var mu sync.Mutex
	var all []ProbeResult
	var wg sync.WaitGroup

	// Local semaphore to limit concurrent probes per port
	probeSem := make(chan struct{}, maxProbeParallel)

	for _, p := range probes {
		wg.Add(1)
		go func(probe NamedProbe) {
			defer wg.Done()

			// Acquire local semaphore (or bail if budget expired)
			select {
			case probeSem <- struct{}{}:
				defer func() { <-probeSem }()
			case <-ctx.Done():
				return
			}

			// Also acquire global semaphore
			acquire()
			defer release()

			// Check budget before running
			if ctx.Err() != nil {
				return
			}

			results := probe.Fn(host, port, timeout)
			if len(results) > 0 {
				mu.Lock()
				all = append(all, results...)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	return aggregateResults(all)
}

// aggregateResults merges duplicate protocol+transport entries using combined probability.
func aggregateResults(results []ProbeResult) []ProbeResult {
	type key struct{ proto, transport string }
	merged := make(map[key]float64)
	for _, r := range results {
		k := key{r.Protocol, r.Transport}
		if prev, ok := merged[k]; ok {
			merged[k] = 100 * (1 - (1-prev/100)*(1-r.Confidence/100))
		} else {
			merged[k] = r.Confidence
		}
	}
	out := make([]ProbeResult, 0, len(merged))
	for k, c := range merged {
		out = append(out, ProbeResult{Protocol: k.proto, Transport: k.transport, Confidence: c})
	}
	return out
}

// ListAllProbes returns names of all registered probes for --list-probes.
func ListAllProbes() []string {
	seen := map[string]bool{}
	var names []string
	for _, p := range AllTCPProbes {
		if !seen[p.Name] {
			names = append(names, p.Name)
			seen[p.Name] = true
		}
	}
	for _, p := range AllUDPProbes {
		if !seen[p.Name] {
			names = append(names, p.Name)
			seen[p.Name] = true
		}
	}
	return names
}
