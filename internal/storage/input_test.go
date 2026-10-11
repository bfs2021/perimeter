package storage_test

import (
	"strings"
	"testing"

	"perimeter/internal/storage"
)

func TestNormalizeTarget(t *testing.T) {
	label64 := strings.Repeat("a", 64)
	// Labels cap at 63, so a 253-char hostname needs four labels.
	label253 := strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61)
	label254 := strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 62)

	tests := []struct {
		name     string
		in       string
		wantNorm string
		wantIP   bool
		wantOK   bool
	}{
		{"hostname", "example.com", "example.com", false, true},
		{"mixed case and trailing dot", "Sub.Example.COM.", "sub.example.com", false, true},
		{"https url with path", "https://example.com/path", "example.com", false, true},
		{"http url", "http://EXAMPLE.com", "example.com", false, true},
		{"upper case scheme", "HTTP://Example.COM/path", "example.com", false, true},
		{"url path only", "https://example.com/", "example.com", false, true},
		{"ipv4", "192.168.1.1", "192.168.1.1", true, true},
		{"ipv4 with spaces", " 192.168.1.1 ", "192.168.1.1", true, true},
		{"ipv6", "2001:db8::1", "2001:db8::1", true, true},
		{"ipv6 mixed case", "2001:DB8::1", "2001:db8::1", true, true},
		{"ipv4 as hostname", "999.999.999.999", "", false, false},
		{"garbage", "not a host!", "", false, false},
		{"leading dash label", "-bad.com", "", false, false},
		{"single label", "localhost", "", false, false},
		{"64 char label", label64 + ".com", "", false, false},
		{"254 char total", label254, "", false, false},
		{"empty", "", "", false, false},
		{"blank", "   ", "", false, false},
		{"scheme only", "https://", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, isIP, ok := storage.NormalizeTarget(tt.in)
			if ok != tt.wantOK || isIP != tt.wantIP || (ok && norm != tt.wantNorm) {
				t.Errorf("NormalizeTarget(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tt.in, norm, isIP, ok, tt.wantNorm, tt.wantIP, tt.wantOK)
			}
		})
	}

	// 253 chars is the limit, so this long hostname is valid.
	if _, _, ok := storage.NormalizeTarget(label253); !ok {
		t.Errorf("253 char hostname rejected")
	}
}
