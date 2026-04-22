package webcheck

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		raw      string
		scheme   string
		host     string
		port     string
		path     string
		explicit bool
	}{
		{"example.com", "https", "example.com", "443", "/", false},
		{"http://example.com/a?b=1", "http", "example.com", "80", "/a?b=1", true},
		{"https://example.com:8443/path", "https", "example.com", "8443", "/path", true},
		{"https://[::1]/", "https", "::1", "443", "/", true},
	}

	for _, tt := range tests {
		got, err := ParseTarget(tt.raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", tt.raw, err)
		}
		if got.Scheme != tt.scheme || got.Host != tt.host || got.Port != tt.port || got.Path != tt.path || got.ExplicitURL != tt.explicit {
			t.Fatalf("ParseTarget(%q) = %+v", tt.raw, got)
		}
	}
}

func TestLimitIPsPrefersIPv4(t *testing.T) {
	got := limitIPs([]string{"2606:4700::1", "1.1.1.1", "8.8.8.8"}, 2)
	want := []string{"1.1.1.1", "8.8.8.8"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("limitIPs mismatch: got %v want %v", got, want)
		}
	}
}
