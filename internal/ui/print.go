package ui

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var (
	successColor = color.New(color.FgGreen).SprintFunc()
	infoColor    = color.New(color.FgCyan).SprintFunc()
	warnColor    = color.New(color.FgYellow).SprintFunc()
	errorColor   = color.New(color.FgRed).SprintFunc()
	bold         = color.New(color.Bold).SprintFunc()
)

func PrintHeader(target string) {
	fmt.Printf("\n🎯 %s: %s\n\n", bold("Target"), infoColor(target))
}

func PrintSection(title string) {
	fmt.Printf("%s\n", bold("["+title+"]"))
}

func PrintResult(name string, err error, extra string) {
	if err == nil {
		fmt.Printf(" %s %s: %s\n", successColor("🟢"), name, infoColor(extra))
	} else {
		// Basic heuristic for warnings vs hard errors
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "unsupported") || strings.Contains(err.Error(), "protocol error") || strings.Contains(err.Error(), "handshake failure") {
			if strings.Contains(strings.ToLower(name), "tls 1.0") || strings.Contains(strings.ToLower(name), "tls 1.1") {
                 fmt.Printf(" %s %s: %s (Secure)\n", successColor("🟢"), name, "Not Supported")
            } else {
                 fmt.Printf(" %s %s: %s\n", warnColor("🟡"), name, warnColor(err.Error()))
            }
		} else {
			fmt.Printf(" %s %s: %s\n", errorColor("🔴"), name, errorColor(err.Error()))
		}
	}
}
