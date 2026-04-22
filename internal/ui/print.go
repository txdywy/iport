package ui

import (
	"fmt"
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
