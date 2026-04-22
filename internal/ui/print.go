package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
)

var (
	mu           sync.Mutex
	successColor = color.New(color.FgGreen).SprintFunc()
	infoColor    = color.New(color.FgCyan).SprintFunc()
	warnColor    = color.New(color.FgYellow).SprintFunc()
	errorColor   = color.New(color.FgRed).SprintFunc()
	bold         = color.New(color.Bold).SprintFunc()
	dimColor     = color.New(color.Faint).SprintFunc()
)

func PrintHeader(target string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\n🎯 %s: %s\n\n", bold("Target"), infoColor(target))
}

func PrintSection(title string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("%s\n", bold("["+title+"]"))
}

func PrintResult(name string, err error, extra string) {
	mu.Lock()
	defer mu.Unlock()
	if err == nil {
		fmt.Printf(" %s %s: %s\n", successColor("🟢"), name, infoColor(extra))
	} else {
		errMsg := err.Error()
		if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "unsupported") || strings.Contains(errMsg, "protocol error") || strings.Contains(errMsg, "handshake failure") {
			if strings.Contains(strings.ToLower(name), "tls 1.0") || strings.Contains(strings.ToLower(name), "tls 1.1") {
				fmt.Printf(" %s %s: %s (Secure)\n", successColor("🟢"), name, "Not Supported")
			} else {
				fmt.Printf(" %s %s: %s\n", warnColor("🟡"), name, warnColor(errMsg))
			}
		} else {
			fmt.Printf(" %s %s: %s\n", errorColor("🔴"), name, errorColor(errMsg))
		}
	}
}

func PrintProgress(total, done int) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\r\033[K⏳ Scanning %d ports: [%d/%d] (%.1f%%)", total, done, total, float64(done)*100/float64(total))
}

func ClearProgress() {
	mu.Lock()
	defer mu.Unlock()
	fmt.Printf("\r\033[K")
}

// ProbeDisplay is a simplified view of a probe result for the UI layer.
type ProbeDisplay struct {
	Protocol   string
	Transport  string
	Confidence float64
}

// PrintProxyResults prints detected proxy protocols for a port, color-coded by confidence.
func PrintProxyResults(port string, results []ProbeDisplay) {
	mu.Lock()
	defer mu.Unlock()

	if len(results) == 0 {
		fmt.Printf(" %s No proxy protocols detected\n", dimColor("⚪"))
		return
	}

	// Sort by confidence descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	for _, r := range results {
		label := r.Protocol
		if r.Transport != "" {
			label += " over " + r.Transport
		}
		conf := fmt.Sprintf("%.0f%%", r.Confidence)

		if r.Confidence >= 80 {
			fmt.Printf(" %s %s %s\n", successColor("🟢"), label, successColor(conf))
		} else if r.Confidence >= 40 {
			fmt.Printf(" %s %s %s\n", warnColor("🟡"), label, warnColor(conf))
		} else {
			fmt.Printf(" %s %s %s\n", dimColor("⚪"), label, dimColor(conf))
		}
	}
}

// PrintProxySummary prints a final summary table of all detected proxy protocols across all ports.
func PrintProxySummary(allResults map[string][]ProbeDisplay) {
	mu.Lock()
	defer mu.Unlock()

	// Collect ports with results
	var ports []string
	for port, results := range allResults {
		if len(results) > 0 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return
	}
	sort.Strings(ports)

	fmt.Printf("\n%s\n", bold("═══ Proxy Protocol Summary ═══"))
	for _, port := range ports {
		results := allResults[port]
		sort.Slice(results, func(i, j int) bool {
			return results[i].Confidence > results[j].Confidence
		})
		for _, r := range results {
			label := r.Protocol
			if r.Transport != "" {
				label += " over " + r.Transport
			}
			conf := fmt.Sprintf("%.0f%%", r.Confidence)

			icon := dimColor("⚪")
			colorFn := dimColor
			if r.Confidence >= 80 {
				icon = successColor("🟢")
				colorFn = successColor
			} else if r.Confidence >= 40 {
				icon = warnColor("🟡")
				colorFn = warnColor
			}
			fmt.Printf(" %s Port %-5s  %-35s %s\n", icon, port, label, colorFn(conf))
		}
	}
	fmt.Println()
}

// PrintProbeList prints all supported probe protocols.
func PrintProbeList(names []string) {
	mu.Lock()
	defer mu.Unlock()

	fmt.Printf("\n%s\n\n", bold("Supported Proxy Protocol Probes"))
	for i, name := range names {
		fmt.Printf("  %2d. %s\n", i+1, name)
	}
	fmt.Printf("\n  Total: %d protocols\n\n", len(names))
}
