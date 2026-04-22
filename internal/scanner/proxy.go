package scanner

import (
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

// RunTCPProbes runs all registered TCP probes concurrently and returns aggregated results.
func RunTCPProbes(host, port string, timeout time.Duration) []ProbeResult {
	return runProbes(AllTCPProbes, host, port, timeout)
}

// RunUDPProbes runs all registered UDP probes concurrently and returns aggregated results.
func RunUDPProbes(host, port string, timeout time.Duration) []ProbeResult {
	return runProbes(AllUDPProbes, host, port, timeout)
}

func runProbes(probes []NamedProbe, host, port string, timeout time.Duration) []ProbeResult {
	var mu sync.Mutex
	var all []ProbeResult
	var wg sync.WaitGroup

	for _, p := range probes {
		wg.Add(1)
		go func(probe NamedProbe) {
			defer wg.Done()
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
			// P(A∪B) = 1 - (1-A)(1-B)
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
