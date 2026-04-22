package netutil

import "testing"

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"[::1]":           "::1",
		"fe80::1%lo0":     "fe80::1",
		"[fe80::1%25en0]": "fe80::1",
		"example.com":     "example.com",
	}
	for in, want := range tests {
		if got := NormalizeHost(in); got != want {
			t.Fatalf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostFormatting(t *testing.T) {
	if got := HostForHTTP("::1"); got != "[::1]" {
		t.Fatalf("HostForHTTP IPv6 = %q", got)
	}
	if got := URLHost("::1", "8443"); got != "[::1]:8443" {
		t.Fatalf("URLHost IPv6 custom port = %q", got)
	}
	if got := URLHost("example.com", "443"); got != "example.com" {
		t.Fatalf("URLHost standard port = %q", got)
	}
}
