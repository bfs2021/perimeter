package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"perimeter/ent"
	"perimeter/ent/importerconfig"
	"perimeter/internal/importer"
)

// fakeSyncer returns a fixed result and records the config it was given.
type fakeSyncer struct {
	err   error
	count int
	cfg   *ent.ImporterConfig
}

func (f *fakeSyncer) SyncOne(_ context.Context, cfg *ent.ImporterConfig) (int, error) {
	f.cfg = cfg
	return f.count, f.err
}

// syncServer is notifierServer with a fake syncer wired in, so the settings
// page the handler re-renders has its importer registry.
func syncServer(t *testing.T) (*Server, *ent.Client, string, *fakeSyncer) {
	t.Helper()
	srv, client, token := notifierServer(t)
	fs := &fakeSyncer{}
	srv.SetImporterSyncer(fs)
	return srv, client, token, fs
}

func createImporterRow(t *testing.T, client *ent.Client) *ent.ImporterConfig {
	t.Helper()
	cfg, err := client.ImporterConfig.Create().
		SetProvider(importerconfig.ProviderGandi).
		SetCredentials([]byte(`{}`)).
		SetSyncIntervalSeconds(3600).
		SetEnabled(true).
		Save(context.Background())
	if err != nil {
		t.Fatalf("create importer: %v", err)
	}
	return cfg
}

func TestSyncImporter(t *testing.T) {
	tests := []struct {
		name    string
		syncErr error
		count   int
		want    string
	}{
		{name: "success", count: 3, want: "Synced gandi: 3 targets imported"},
		{name: "failure", syncErr: errors.New("boom"), want: "Sync failed: boom"},
		{name: "already running", syncErr: importer.ErrSyncRunning, want: "Sync already running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, client, token, fs := syncServer(t)
			cfg := createImporterRow(t, client)
			fs.err, fs.count = tt.syncErr, tt.count

			resp := postForm(t, srv, token, fmt.Sprintf("/importers/%d/sync", cfg.ID), url.Values{})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200 with the settings page; body:\n%s", resp.StatusCode, resp.Body)
			}
			if !strings.Contains(resp.Body, tt.want) {
				t.Errorf("page does not show %q", tt.want)
			}
			if fs.cfg == nil || fs.cfg.ID != cfg.ID {
				t.Errorf("syncer called with %v, want the imported config", fs.cfg)
			}
		})
	}
}

func TestSyncImporterNotFound(t *testing.T) {
	srv, _, token, _ := syncServer(t)

	resp := postForm(t, srv, token, "/importers/999/sync", url.Values{})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404; body:\n%s", resp.StatusCode, resp.Body)
	}
}
