package service_test

import (
	"fmt"
	"testing"
	"time"

	"perimeter/internal/service"
)

// wantChange is one expected change. "*" in From or To means "not checked";
// the certificate dates are RFC 3339 strings, which the test does not spell out.
type wantChange struct {
	kind, target, ip, from, to string
}

func assertChanges(t *testing.T, got []service.Change, want []wantChange) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d changes, want %d:\n%s", len(got), len(want), describe(got))
	}
	for i, w := range want {
		g := got[i]
		ok := g.Kind == w.kind && g.Target == w.target && g.IP == w.ip &&
			(w.from == "*" || g.From == w.from) && (w.to == "*" || g.To == w.to)
		if !ok {
			t.Errorf("change %d = %s %s ip=%q from=%q to=%q (%s), want %s %s ip=%q from=%q to=%q",
				i, g.Kind, g.Target, g.IP, g.From, g.To, g.Summary, w.kind, w.target, w.ip, w.from, w.to)
		}
	}
}

func describe(cs []service.Change) string {
	s := ""
	for _, c := range cs {
		s += fmt.Sprintf("  %s %s %s\n", c.Kind, c.Target, c.Summary)
	}
	return s
}

// settle returns a time after every row written so far, and lets the clock
// move on so that the next writes are strictly later.
func settle() time.Time {
	now := time.Now()
	time.Sleep(time.Millisecond)
	return now
}

func TestChangesSince(t *testing.T) {
	f := newFixture(t)
	exp2027 := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	exp2028 := time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)

	// Before the window: these rows are the baseline, not changes.
	f.target("a.test")
	f.ip("a.test", "10.0.0.1")
	f.ports("10.0.0.1", 22, 443)
	f.ssl("a.test", "A", exp2027)
	f.csp("a.test", 2)
	f.target("b.test")
	f.ssl("b.test", "B", exp2027)
	since := settle()

	f.ssl("a.test", "C", exp2027)                                  // grade A -> C
	f.ssl("a.test", "C", exp2028)                                  // certificate renewed
	f.ssl("a.test", "C", exp2028)                                  // unchanged: no row
	f.ports("10.0.0.1", 22, 443, 8080)                             // 8080 opened
	f.ports("10.0.0.1", 443, 8080)                                 // 22 closed
	f.ports("10.0.0.1", 443, 8080)                                 // unchanged: no row
	f.must(f.st.SavePortScanError(f.ctx, "10.0.0.1", "no answer")) // became unreachable
	f.must(f.st.SavePortScanError(f.ctx, "10.0.0.1", "no answer")) // repeated error: no row
	f.ports("10.0.0.1", 443)                                       // reachable again, and 8080 closed
	f.csp("a.test", 3)                                             // 2 -> 3 findings
	f.csp("a.test", 3)                                             // unchanged: no row
	f.target("c.test")                                             // added
	f.ip("c.test", "10.0.0.3")
	f.ports("10.0.0.3", 80)                          // first port scan of an IP: not a change
	f.ssl("c.test", "B", exp2027)                    // first SSL grade: "" -> B
	f.must(f.st.DeleteTarget(f.ctx, f.id("b.test"))) // deleted

	want := []wantChange{
		{kind: service.ChangeSSLGradeChanged, target: "a.test", from: "A", to: "C"},
		{kind: service.ChangeCertRenewed, target: "a.test", from: "*", to: "*"},
		{kind: service.ChangePortsOpened, target: "a.test", ip: "10.0.0.1", to: "8080"},
		{kind: service.ChangePortsClosed, target: "a.test", ip: "10.0.0.1", from: "22"},
		{kind: service.ChangeBecameUnreachable, target: "a.test", ip: "10.0.0.1", from: "reachable", to: "unreachable"},
		{kind: service.ChangeBecameReachable, target: "a.test", ip: "10.0.0.1", from: "unreachable", to: "reachable"},
		{kind: service.ChangePortsClosed, target: "a.test", ip: "10.0.0.1", from: "8080"},
		{kind: service.ChangeCSPChanged, target: "a.test", from: "2 findings", to: "3 findings"},
		{kind: service.ChangeTargetAdded, target: "c.test"},
		{kind: service.ChangeSSLGradeChanged, target: "c.test", from: "", to: "B"},
		{kind: service.ChangeTargetDeleted, target: "b.test"},
	}

	got, truncated, err := f.svc.ChangesSince(f.ctx, since, 0)
	f.must(err)
	if truncated {
		t.Error("truncated with 11 changes under the default limit")
	}
	assertChanges(t, got, want)
	if got[0].Summary != "a.test: SSL grade A → C" {
		t.Errorf("summary = %q", got[0].Summary)
	}
	if got[4].Summary != "a.test: 10.0.0.1 unreachable (no answer)" {
		t.Errorf("summary = %q", got[4].Summary)
	}

	// The limit cuts the oldest-first list and says so.
	head, truncated, err := f.svc.ChangesSince(f.ctx, since, 3)
	f.must(err)
	if !truncated {
		t.Error("limit 3 of 11 changes should be truncated")
	}
	assertChanges(t, head, want[:3])

	// Re-scanning with the same results writes nothing, so nothing changes.
	quiet := settle()
	f.ssl("a.test", "C", exp2028)
	f.ports("10.0.0.1", 443)
	f.csp("a.test", 3)
	f.ssl("c.test", "B", exp2027)
	none, truncated, err := f.svc.ChangesSince(f.ctx, quiet, 0)
	f.must(err)
	if len(none) != 0 || truncated {
		t.Errorf("unchanged re-scans produced changes:\n%s", describe(none))
	}
}

func TestChangesSinceUnreachableFromTheFirstRow(t *testing.T) {
	f := newFixture(t)
	f.target("10.0.0.7")
	f.ip("10.0.0.7", "10.0.0.7")
	f.must(f.st.SavePortScanError(f.ctx, "10.0.0.7", "timeout"))
	since := settle()
	f.ports("10.0.0.7", 22)

	// No port list was ever answered before the window, so there is nothing
	// to diff the new ports against: only the reachability change is reported.
	got, _, err := f.svc.ChangesSince(f.ctx, since, 0)
	f.must(err)
	assertChanges(t, got, []wantChange{
		{kind: service.ChangeBecameReachable, target: "10.0.0.7", ip: "10.0.0.7", from: "unreachable", to: "reachable"},
	})
}
