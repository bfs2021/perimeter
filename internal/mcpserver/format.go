package mcpserver

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"perimeter/internal/service"
)

// timeLayout is how times read in text: minute precision, UTC, no zone name
// to parse.
const timeLayout = "2006-01-02 15:04 UTC"

// targetLine is one target as a list line, e.g.
// "#12 example.com · A · cert 23d · 2 open ports · CSP 2 findings · tags: prod".
// Fields that do not apply are left out.
func targetLine(s service.TargetSummary) string {
	parts := []string{fmt.Sprintf("#%d %s", s.ID, s.Input)}
	if s.Reachability != "ok" {
		parts = append(parts, s.Reachability)
	}
	if s.SSLGrade != "" {
		parts = append(parts, s.SSLGrade)
	}
	if c := certText(s); c != "" {
		parts = append(parts, c)
	}
	switch {
	case s.OpenPorts == 1:
		parts = append(parts, "1 open port")
	case s.OpenPorts > 1:
		parts = append(parts, fmt.Sprintf("%d open ports", s.OpenPorts))
	}
	if s.CSPFindings != nil {
		parts = append(parts, cspText(*s.CSPFindings))
	}
	if len(s.Tags) > 0 {
		parts = append(parts, "tags: "+strings.Join(s.Tags, ", "))
	}
	if s.DeletedAt != nil {
		parts = append(parts, "deleted")
	}
	return strings.Join(parts, " · ")
}

// certText is the certificate part of a line: days left, or how long ago it
// expired. It is empty when no certificate has been seen.
func certText(s service.TargetSummary) string {
	if s.CertDaysLeft == nil {
		return ""
	}
	if d := *s.CertDaysLeft; d < 0 {
		return fmt.Sprintf("cert expired %dd ago", -d)
	}
	return fmt.Sprintf("cert %dd", *s.CertDaysLeft)
}

// cspText reads a finding count; zero is the good case, so it says so.
func cspText(n int) string {
	if n == 0 {
		return "CSP ok"
	}
	return fmt.Sprintf("CSP %d findings", n)
}

// moreText says how to reach the rest of a list, or "" when the page is the
// end of it. offset is the offset the page was read at.
func moreText(total, offset, shown int) string {
	rest := total - offset - shown
	if rest <= 0 {
		return ""
	}
	return fmt.Sprintf("%d more; pass offset=%d for the next page", rest, offset+shown)
}

// joinIDs formats target ids as "#3, #5".
func joinIDs(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "#"+strconv.Itoa(id))
	}
	return strings.Join(parts, ", ")
}

// formatTime is a time in the text form.
func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}
