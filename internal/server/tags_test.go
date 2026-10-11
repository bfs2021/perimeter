package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Tag action failures re-render the settings page with a friendly message;
// driver errors must not leak into it.
func TestDeleteUnknownTagShowsFriendlyError(t *testing.T) {
	srv, _, token := authedServer(t)

	resp := postForm(t, srv, token, "/tags/999999/delete", url.Values{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 with the settings page; body:\n%s", resp.StatusCode, resp.Body)
	}
	// "ent: tag" is ent's driver error prefix; it must never reach the page.
	if strings.Contains(resp.Body, "ent: tag") {
		t.Errorf("driver error leaked to the page: %q", resp.Body)
	}
	if !strings.Contains(resp.Body, "Failed to delete tag: it no longer exists") {
		t.Errorf("friendly message missing; body:\n%s", resp.Body)
	}
}

func TestCreateDuplicateTagShowsFriendlyError(t *testing.T) {
	srv, client, token := authedServer(t)
	if _, err := client.Tag.Create().SetName("prod").Save(context.Background()); err != nil {
		t.Fatalf("create tag: %v", err)
	}

	resp := postForm(t, srv, token, "/tags", url.Values{"name": {"prod"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 with the settings page; body:\n%s", resp.StatusCode, resp.Body)
	}
	if strings.Contains(resp.Body, "ent: tag") {
		t.Errorf("driver error leaked to the page: %q", resp.Body)
	}
	if !strings.Contains(resp.Body, "Failed to create tag: an entry with that name already exists") {
		t.Errorf("friendly message missing; body:\n%s", resp.Body)
	}
}
