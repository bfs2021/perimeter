package server

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent"
	"perimeter/ent/target"
)

// createTags creates the named tags and returns their ids in order.
func createTags(t *testing.T, client *ent.Client, names ...string) []int {
	t.Helper()
	ids := make([]int, len(names))
	for i, name := range names {
		tag, err := client.Tag.Create().SetName(name).Save(context.Background())
		if err != nil {
			t.Fatalf("create tag %s: %v", name, err)
		}
		ids[i] = tag.ID
	}
	return ids
}

// targetTagIDs returns the ids of the tags attached to a target, sorted.
func targetTagIDs(t *testing.T, client *ent.Client, targetID int) []int {
	t.Helper()
	tg, err := client.Target.Query().Where(target.ID(targetID)).WithTags().Only(context.Background())
	if err != nil {
		t.Fatalf("load target %d: %v", targetID, err)
	}
	ids := make([]int, len(tg.Edges.Tags))
	for i, tag := range tg.Edges.Tags {
		ids[i] = tag.ID
	}
	slices.Sort(ids)
	return ids
}

func TestImportSubmitRendersResult(t *testing.T) {
	srv, client, token := authedServer(t)

	form := url.Values{"source": {"manual"}}
	form.Set("manual_input", "example.com\n999.999.999.999\nexample.com")
	resp := postForm(t, srv, token, "/import", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /import: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if strings.Contains(resp.Body, "template: views/") {
		t.Fatalf("template error in output:\n%s", resp.Body)
	}
	if !strings.Contains(resp.Body, "1 added, 0 already present, 0 restored, 1 invalid") {
		t.Errorf("summary line missing:\n%s", resp.Body)
	}
	if !strings.Contains(resp.Body, "<li>999.999.999.999</li>") {
		t.Errorf("invalid line not listed:\n%s", resp.Body)
	}
	if !strings.Contains(resp.Body, `href="/"`) {
		t.Errorf("back-to-dashboard link missing")
	}
	if !strings.Contains(resp.Body, ">999.999.999.999</textarea>") {
		t.Errorf("textarea not prefilled with the invalid line:\n%s", resp.Body)
	}

	// example.com was imported once, the duplicate collapsed, the garbage was
	// not stored.
	n, err := client.Target.Query().Count(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("target count %d (err %v), want 1", n, err)
	}
	tg, err := client.Target.Query().Only(context.Background())
	if err != nil || tg.Input != "example.com" {
		t.Errorf("stored target %+v (err %v), want example.com", tg, err)
	}
}

func TestUpdateTargetTagsValidation(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	ids := importTargets(t, client, "a.example.com")
	tid := ids["a.example.com"]
	tagIDs := createTags(t, client, "prod", "staging")
	prod, staging := tagIDs[0], tagIDs[1]

	if err := client.Target.UpdateOneID(tid).AddTagIDs(prod, staging).Exec(ctx); err != nil {
		t.Fatalf("attach tags: %v", err)
	}
	path := "/targets/" + strconv.Itoa(tid) + "/tags"

	// Non-numeric value: 400, tags untouched.
	form := url.Values{}
	form.Add("tags", "abc")
	resp := postForm(t, srv, token, path, form)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(resp.Body, "Invalid tag id") {
		t.Fatalf("non-numeric: status %d, body %q", resp.StatusCode, resp.Body)
	}
	if got := targetTagIDs(t, client, tid); !slices.Equal(got, []int{prod, staging}) {
		t.Errorf("tags after rejected update = %v, want both", got)
	}

	// Unknown id among valid ones: 400, tags untouched.
	form = url.Values{}
	form.Add("tags", strconv.Itoa(prod))
	form.Add("tags", "999999")
	resp = postForm(t, srv, token, path, form)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(resp.Body, "Unknown tag") {
		t.Fatalf("unknown id: status %d, body %q", resp.StatusCode, resp.Body)
	}
	if got := targetTagIDs(t, client, tid); !slices.Equal(got, []int{prod, staging}) {
		t.Errorf("tags after rejected update = %v, want both", got)
	}

	// Valid ids replace the tags; duplicates collapse.
	form = url.Values{}
	form.Add("tags", strconv.Itoa(staging))
	form.Add("tags", strconv.Itoa(staging))
	resp = postForm(t, srv, token, path, form)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/targets/"+strconv.Itoa(tid) {
		t.Fatalf("valid ids: status %d, location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := targetTagIDs(t, client, tid); !slices.Equal(got, []int{staging}) {
		t.Errorf("tags after valid update = %v, want only staging", got)
	}

	// No values clears all tags.
	resp = postForm(t, srv, token, path, url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("clear: status %d", resp.StatusCode)
	}
	if got := targetTagIDs(t, client, tid); len(got) != 0 {
		t.Errorf("tags after clear = %v, want none", got)
	}
}
