package csp

import "testing"

func TestSeverityLevel(t *testing.T) {
	cases := []struct {
		name     string
		severity Severity
		want     string
	}{
		{"high", SeverityHigh, "high"},
		{"syntax", SeveritySyntax, "high"},
		{"medium", SeverityMedium, "medium"},
		{"high maybe", SeverityHighMaybe, "medium"},
		{"strict csp", SeverityStrictCSP, "low"},
		{"medium maybe", SeverityMediumMaybe, "low"},
		{"info", SeverityInfo, "info"},
		{"none", SeverityNone, "info"},
		{"past none", Severity(70), "info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.severity.Level(); got != tc.want {
				t.Errorf("Level() = %q, want %q", got, tc.want)
			}
		})
	}
}
