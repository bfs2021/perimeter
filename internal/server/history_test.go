package server

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"perimeter/ent"
)

func portScanWith(numbers ...int) *ent.PortScan {
	scan := &ent.PortScan{}
	for _, n := range numbers {
		scan.Edges.Ports = append(scan.Edges.Ports, &ent.Port{Number: n})
	}
	return scan
}

// The target page is the only caller of the partial, and no handler test
// reaches it, so render it directly: an error row must show the scan failed
// badge (error in the title and visible text) and no diff, the normal row its
// ports with the changes: prefix, and the old static legend must be gone.
func TestIpSectionRendersScanError(t *testing.T) {
	engine := newViewEngine(os.DirFS("../.."))
	const errMsg = "host unreachable: no route to host"
	data := ipScanRow{
		IP: &ent.IP{},
		Scans: []portScanView{
			{PortScan: &ent.PortScan{CheckCount: 2, ScanError: errMsg}},
			{PortScan: portScanWith(80), Added: []int{443}},
		},
		Pagination: pagination{Page: 1, TotalPages: 1},
	}

	var buf bytes.Buffer
	if err := engine.Render(&buf, "views/partials/ip_section", data); err != nil {
		t.Fatalf("render ip_section: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<span class="badge badge-gray" title="`+errMsg+`">scan failed</span>`) {
		t.Errorf("missing scan failed badge:\n%s", out)
	}
	if !strings.Contains(out, errMsg) {
		t.Errorf("missing error text:\n%s", out)
	}
	if strings.Contains(out, "+N opened") {
		t.Errorf("static legend still rendered:\n%s", out)
	}
	if !strings.Contains(out, `changes: +443`) {
		t.Errorf("missing changes prefix:\n%s", out)
	}
	if !strings.Contains(out, `<span class="badge badge-red">80</span>`) {
		t.Errorf("missing port badge:\n%s", out)
	}
}

func TestPortDelta(t *testing.T) {
	added, removed := portDelta([]int{22, 80, 3306}, []int{80, 22, 8080})
	if !slices.Equal(added, []int{8080}) {
		t.Errorf("added = %v, want [8080]", added)
	}
	if !slices.Equal(removed, []int{3306}) {
		t.Errorf("removed = %v, want [3306]", removed)
	}

	added, removed = portDelta([]int{80}, []int{80})
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("unchanged set produced %v / %v", added, removed)
	}
}

func TestDiffPortScansSkipsErrorRows(t *testing.T) {
	// Newest first: error row, answered row, error row, answered row.
	items := []*ent.PortScan{
		{ScanError: "host unreachable"},
		portScanWith(80, 443),
		{ScanError: "host unreachable"},
		portScanWith(80),
	}

	views := diffPortScans(items)
	if len(views) != 4 {
		t.Fatalf("got %d rows, want 4", len(views))
	}
	// Error rows show no diff at all.
	for _, idx := range []int{0, 2} {
		if len(views[idx].Added) != 0 || len(views[idx].Removed) != 0 {
			t.Errorf("error row %d got a diff: %v / %v", idx, views[idx].Added, views[idx].Removed)
		}
	}
	// The answered row diffs against the next older answered row, skipping
	// the error row in between.
	if !slices.Equal(views[1].Added, []int{443}) {
		t.Errorf("row 1: added %v, want [443]", views[1].Added)
	}
	if len(views[1].Removed) != 0 {
		t.Errorf("row 1: removed %v, want none", views[1].Removed)
	}
	// The oldest row has no baseline.
	if len(views[3].Added) != 0 || len(views[3].Removed) != 0 {
		t.Errorf("oldest row got a diff: %v / %v", views[3].Added, views[3].Removed)
	}
}

func TestDiffPortScansDropsLookaheadRow(t *testing.T) {
	// Newest first, one row past a full page.
	items := make([]*ent.PortScan, 0, scanPageSize+1)
	for range scanPageSize {
		items = append(items, portScanWith(80, 443))
	}
	items = append(items, portScanWith(80))

	views := diffPortScans(items)
	if len(views) != scanPageSize {
		t.Fatalf("got %d rows, want %d", len(views), scanPageSize)
	}
	last := views[len(views)-1]
	if !slices.Equal(last.Added, []int{443}) {
		t.Errorf("oldest row on page: added %v, want [443]", last.Added)
	}
	if len(views[0].Added) != 0 || len(views[0].Removed) != 0 {
		t.Errorf("unchanged row got a diff: %v / %v", views[0].Added, views[0].Removed)
	}
}
