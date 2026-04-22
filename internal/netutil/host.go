package netutil

import "strings"

// NormalizeHost strips brackets and zone IDs from a host string for use in dial/SNI.
// "[::1]" -> "::1", "fe80::1%lo0" -> "fe80::1", "[fe80::1%25lo0]" -> "fe80::1".
func NormalizeHost(host string) string {
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

// HostForHTTP returns a host suitable for HTTP Host headers and URLs.
// IPv6 literals get brackets, regular hosts pass through.
func HostForHTTP(host string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// URLHost returns a host string safe for URLs, omitting common default ports.
func URLHost(host, port string) string {
	return URLHostForScheme(host, port, "")
}

// URLHostForScheme returns a host string safe for URLs, omitting only the
// default port for the given scheme.
func URLHostForScheme(host, port, scheme string) string {
	h := HostForHTTP(host)
	switch scheme {
	case "http":
		if port == "80" {
			return h
		}
	case "https":
		if port == "443" {
			return h
		}
	default:
		if port == "80" || port == "443" {
			return h
		}
	}
	if port == "" {
		return h
	}
	return h + ":" + port
}
