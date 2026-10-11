package storage

import (
	"net"
	"strings"
)

// NormalizeTarget validates a target line and returns its canonical form:
// the IP string for IP addresses, the lowercased hostname otherwise. URLs
// are reduced to their host. ok is false when the line is neither a valid IP
// nor a valid hostname, e.g. "999.999.999.999" or "not a host!".
func NormalizeTarget(s string) (normalized string, isIP bool, ok bool) {
	// Lowercase first so scheme stripping is case-insensitive ("HTTP://").
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")

	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true, true
	}
	return s, false, isHostname(s)
}

// isHostname accepts dot-separated labels of 1..63 chars of [a-z0-9-] that
// do not start or end with a dash, a total of at most 253 chars, at least two
// labels, and a TLD that is not all digits (the all-digit shape is the dotted
// form of an IP, not a hostname).
func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !isLabelChar(r) {
				return false
			}
		}
	}
	return !allDigits(labels[len(labels)-1])
}

func isLabelChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
