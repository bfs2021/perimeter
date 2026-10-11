package server

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/storage"
	"perimeter/scanner/csp"
)

// exportFixture adds a target with one IP, a port scan, two SSL scans and two
// CSP scans, all with fixed UTC times so exported output is deterministic.
func exportFixture(t *testing.T, client *ent.Client, input string) int {
	t.Helper()
	ctx := context.Background()
	at := func(h int) time.Time { return time.Date(2026, 1, 2, h, 4, 5, 0, time.UTC) }

	tg, err := client.Target.Create().SetInput(input).SetReachability("ok").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	ip, err := client.IP.Create().SetAddress("192.0.2.10").AddTargetIDs(tg.ID).Save(ctx)
	if err != nil {
		t.Fatalf("create ip: %v", err)
	}
	scan, err := client.PortScan.Create().SetScannedAt(at(1)).SetIPID(ip.ID).Save(ctx)
	if err != nil {
		t.Fatalf("create port scan: %v", err)
	}
	for _, n := range []int{80, 443} {
		if _, err := client.Port.Create().SetNumber(n).SetScanID(scan.ID).Save(ctx); err != nil {
			t.Fatalf("create port: %v", err)
		}
	}
	if _, err := client.SSLScan.Create().SetScannedAt(at(2)).SetGrade("A").SetStatus("READY").
		SetCertIssuer("Test CA").SetCertSubject(input).SetCertExpiry(at(3)).
		SetVulnerabilities([]string{"POODLE"}).SetTargetID(tg.ID).Save(ctx); err != nil {
		t.Fatalf("create ssl scan: %v", err)
	}
	if _, err := client.SSLScan.Create().SetScannedAt(at(4)).SetGrade("B").SetStatus("READY").SetTargetID(tg.ID).Save(ctx); err != nil {
		t.Fatalf("create ssl scan: %v", err)
	}
	if _, err := client.CSPScan.Create().SetScannedAt(at(5)).SetCspHeader("default-src 'self'").
		SetFindings([]csp.Finding{{Type: 1, Description: "d", Directive: "script-src", Value: "*"}}).
		SetTargetID(tg.ID).Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}
	if _, err := client.CSPScan.Create().SetScannedAt(at(6)).SetCspHeader("").SetProbeError("connection refused").
		SetTargetID(tg.ID).Save(ctx); err != nil {
		t.Fatalf("create csp scan: %v", err)
	}
	return tg.ID
}

// Error rows carry scan_error and a successful scan with no ports exports
// ports as [], not null (issue #29).
func TestExportPortScanErrorAndEmptyPorts(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()
	at := func(h int) time.Time { return time.Date(2026, 1, 2, h, 4, 5, 0, time.UTC) }

	tg, err := client.Target.Create().SetInput("err.example").SetReachability("unreachable").Save(ctx)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	ip, err := client.IP.Create().SetAddress("192.0.2.20").AddTargetIDs(tg.ID).Save(ctx)
	if err != nil {
		t.Fatalf("create ip: %v", err)
	}
	if _, err := client.PortScan.Create().SetScannedAt(at(1)).SetIPID(ip.ID).Save(ctx); err != nil {
		t.Fatalf("create empty port scan: %v", err)
	}
	const errMsg = "host unreachable: dial tcp 192.0.2.20:80: connect: no route to host"
	if _, err := client.PortScan.Create().SetScannedAt(at(2)).SetIPID(ip.ID).SetScanError(errMsg).Save(ctx); err != nil {
		t.Fatalf("create error port scan: %v", err)
	}

	tgt, err := storage.NewEntStorage(client).GetTarget(ctx, tg.ID)
	if err != nil {
		t.Fatalf("GetTarget: %v", err)
	}
	data := newExportData(tgt)
	if len(data.IPs) != 1 || len(data.IPs[0].Scans) != 2 {
		t.Fatalf("scans = %v, want 2 scans for 1 IP", data.IPs)
	}
	// Newest first.
	errScan, emptyScan := data.IPs[0].Scans[0], data.IPs[0].Scans[1]
	if errScan.Error != errMsg {
		t.Errorf("error scan = %q, want %q", errScan.Error, errMsg)
	}
	if len(errScan.Ports) != 0 {
		t.Errorf("error scan ports = %v, want none", errScan.Ports)
	}
	if emptyScan.Error != "" {
		t.Errorf("successful scan error = %q, want empty", emptyScan.Error)
	}
	if emptyScan.Ports == nil || len(emptyScan.Ports) != 0 {
		t.Errorf("successful empty scan ports = %#v, want []", emptyScan.Ports)
	}
	b, err := json.Marshal(emptyScan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"scanned_at":"2026-01-02T01:04:05Z","ports":[]}` {
		t.Errorf("empty scan JSON = %s, want [] ports", b)
	}

	var portRows [][]string
	for _, row := range exportCSVRows(data) {
		if row[0] == "port_scan" {
			portRows = append(portRows, row)
		}
	}
	if len(portRows) != 2 {
		t.Fatalf("got %d port_scan rows, want 2", len(portRows))
	}
	if portRows[0][3] != errMsg {
		t.Errorf("error row value = %q, want the error text", portRows[0][3])
	}
	if portRows[1][3] != "" {
		t.Errorf("empty scan value = %q, want empty", portRows[1][3])
	}
}

// TestSingleTargetExportGolden pins the single-target export bytes. The
// export refactor must leave them unchanged.
func TestSingleTargetExportGolden(t *testing.T) {
	srv, client, token := authedServer(t)
	id := exportFixture(t, client, "example.com")
	path := "/targets/" + strconv.Itoa(id) + "/export"

	cases := []struct {
		query  string
		golden string
		ctype  string
		ext    string
	}{
		{"", "testdata/export_single.golden.json", "application/json", "json"},
		{"?format=json", "testdata/export_single.golden.json", "application/json", "json"},
		{"?format=csv", "testdata/export_single.golden.csv", "text/csv", "csv"},
	}
	for _, tc := range cases {
		want, err := os.ReadFile(tc.golden)
		if err != nil {
			t.Fatalf("reading %s: %v", tc.golden, err)
		}
		resp := send(t, srv, token, "GET", path+tc.query, "", "")
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status %d", path+tc.query, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != tc.ctype {
			t.Errorf("GET %s: Content-Type %q, want %q", path+tc.query, got, tc.ctype)
		}
		if got, want := resp.Header.Get("Content-Disposition"), "attachment; filename=example.com."+tc.ext; got != want {
			t.Errorf("GET %s: Content-Disposition %q, want %q", path+tc.query, got, want)
		}
		if resp.Body != string(want) {
			t.Errorf("GET %s: body differs from %s:\n%s", path+tc.query, tc.golden, resp.Body)
		}
	}
}
