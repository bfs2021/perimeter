package server

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/scanner/csp"
)

// An unknown target id renders the styled error page, not bare text.
func TestUnknownTargetRendersErrorPage(t *testing.T) {
	srv, _, token := authedServer(t)

	resp := send(t, srv, token, "GET", "/targets/999999", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /targets/999999: status %d, want 404; body:\n%s", resp.StatusCode, resp.Body)
	}
	for _, want := range []string{"Back to dashboard", "Target not found"} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("error page missing %q; body:\n%s", want, resp.Body)
		}
	}
}

func TestTargetDetailsCSPSeverityBadges(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	tg, err := client.Target.Create().SetInput("csp.example.com").SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	findings := []csp.Finding{
		{Type: csp.TypeScriptUnsafeInline, Directive: "script-src", Severity: csp.SeverityHigh, Description: "unsafe-inline allowed"},
		{Type: csp.TypeReportingDestinationMissing, Directive: "report-to", Severity: csp.SeverityInfo, Description: "reporting destination missing"},
	}
	if _, err := client.CSPScan.Create().SetScannedAt(time.Now().UTC()).SetCspHeader("default-src 'self'").
		SetFindings(findings).SetTargetID(tg.ID).Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}

	resp := send(t, srv, token, "GET", "/targets/"+strconv.Itoa(tg.ID), "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET /targets/%d: status %d, body:\n%s", tg.ID, resp.StatusCode, resp.Body)
	}
	if strings.Contains(resp.Body, "template: views/") {
		t.Fatalf("template execution error in output:\n%s", resp.Body)
	}

	// Each finding row renders its badge directly above its directive.
	re := regexp.MustCompile(`<span class="badge (badge-\w+)">(\w+)</span>\s*<strong>([^<]+)</strong>`)
	levels := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(resp.Body, -1) {
		levels[m[3]] = m[1] + "/" + m[2]
	}
	if got := levels["script-src"]; got != "badge-red/high" {
		t.Errorf("high finding badge %q, want badge-red/high", got)
	}
	if got := levels["report-to"]; got != "badge-gray/info" {
		t.Errorf("info finding badge %q, want badge-gray/info", got)
	}
}
