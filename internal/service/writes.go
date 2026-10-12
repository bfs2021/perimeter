package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/schema"
	"perimeter/ent/tag"
	"perimeter/ent/target"
	"perimeter/ent/user"
	"perimeter/internal/importer"
	"perimeter/internal/storage"
)

const (
	// maxImportLines caps one import call, so a single request cannot queue
	// an unbounded amount of work.
	maxImportLines = 1000
	// maxRescanIDs caps one rescan call, the same as the UI's bulk actions
	// allow per query.
	maxRescanIDs = 500
)

// ImportResult says what an import did with each line. Lists are never null.
type ImportResult struct {
	Added    []string    `json:"added"`
	Existing []string    `json:"existing"`
	Restored []string    `json:"restored"`
	Invalid  []string    `json:"invalid"`
	Targets  []TargetRef `json:"targets"`
}

// TargetRef names one target an import touched. Status is "added",
// "existing" or "restored".
type TargetRef struct {
	ID     int    `json:"id"`
	Input  string `json:"input"`
	Status string `json:"status"`
}

// RescanResult says what happened to each requested id.
type RescanResult struct {
	Queued      []int            `json:"queued"`
	CoolingDown []RescanCooldown `json:"cooling_down"`
	NotFound    []int            `json:"not_found"`
}

// RescanCooldown is a target that was rescanned too recently, and when it may
// be rescanned again.
type RescanCooldown struct {
	ID      int       `json:"id"`
	RetryAt time.Time `json:"retry_at"`
}

// CanWrite reports whether a caller may change data: the user must be an
// admin or a member, and an API token must have write scope. A nil token is
// a session. The role is read live, so a demotion applies at once.
func CanWrite(u *ent.User, tok *ent.APIToken) bool {
	if u == nil || (u.Role != user.RoleAdmin && u.Role != user.RoleMember) {
		return false
	}
	return tok == nil || tok.Scope == apitoken.ScopeWrite
}

// ImportTargets adds targets the way the UI import does: the same parser and
// normalization, and a soft-deleted match is restored with its history.
func (s *Service) ImportTargets(ctx context.Context, a Actor, inputs []string) (*ImportResult, error) {
	src := &importer.ManualSource{Input: strings.Join(inputs, "\n")}
	lines, err := src.Fetch(ctx)
	if err != nil {
		return nil, err
	}
	if len(lines) > maxImportLines {
		return nil, invalid("inputs", "at most %d lines per call, got %d", maxImportLines, len(lines))
	}

	res, err := s.st.ImportTargetsReport(ctx, lines)
	if err != nil {
		return nil, err
	}
	refs, err := s.importRefs(ctx, res)
	if err != nil {
		return nil, err
	}

	object, detail := ImportAudit(res)
	s.Audit(ctx, a, "target.import", object, detail)
	return &ImportResult{
		Added:    orEmpty(res.Added),
		Existing: orEmpty(res.Existing),
		Restored: orEmpty(res.Restored),
		Invalid:  orEmpty(res.Invalid),
		Targets:  refs,
	}, nil
}

// importRefs looks up the ids of the targets an import touched, in id order.
func (s *Service) importRefs(ctx context.Context, res storage.ImportResult) ([]TargetRef, error) {
	statuses := make(map[string]string)
	var inputs []string
	for _, g := range []struct {
		names  []string
		status string
	}{{res.Added, "added"}, {res.Existing, "existing"}, {res.Restored, "restored"}} {
		for _, in := range g.names {
			statuses[in] = g.status
			inputs = append(inputs, in)
		}
	}
	refs := []TargetRef{}
	if len(inputs) == 0 {
		return refs, nil
	}
	rows, err := s.client.Target.Query().Where(target.InputIn(inputs...)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range rows {
		refs = append(refs, TargetRef{ID: t.ID, Input: t.Input, Status: statuses[t.Input]})
	}
	slices.SortFunc(refs, func(x, y TargetRef) int { return x.ID - y.ID })
	return refs, nil
}

// tagMode is how a tag write changes a target's tags.
type tagMode int

const (
	tagSet tagMode = iota
	tagAdd
	tagRemove
)

// SetTargetTags replaces the tags of a live target with tagNames. An empty
// list clears them.
func (s *Service) SetTargetTags(ctx context.Context, a Actor, id int, tagNames []string) (*TargetSummary, error) {
	return s.changeTags(ctx, a, id, tagNames, tagSet)
}

// AddTargetTags adds tagNames to a live target, keeping the tags it has.
func (s *Service) AddTargetTags(ctx context.Context, a Actor, id int, tagNames []string) (*TargetSummary, error) {
	return s.changeTags(ctx, a, id, tagNames, tagAdd)
}

// RemoveTargetTags removes tagNames from a live target. Names the target does
// not carry are ignored.
func (s *Service) RemoveTargetTags(ctx context.Context, a Actor, id int, tagNames []string) (*TargetSummary, error) {
	return s.changeTags(ctx, a, id, tagNames, tagRemove)
}

// changeTags applies one tag write and audits the names that actually changed.
func (s *Service) changeTags(ctx context.Context, a Actor, id int, names []string, mode tagMode) (*TargetSummary, error) {
	t, err := s.liveTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	tags, err := s.tagsByName(ctx, names)
	if err != nil {
		return nil, err
	}

	var present []string
	for _, g := range t.Edges.Tags {
		present = append(present, g.Name)
	}
	upd := s.client.Target.UpdateOne(t)
	var changed []string
	switch mode {
	case tagSet:
		// Same as the UI: clear, then add the new set in one update.
		upd.ClearTags().AddTagIDs(tagIDs(tags)...)
		for _, g := range tags {
			changed = append(changed, g.Name)
		}
	case tagAdd:
		var add []int
		for _, g := range tags {
			if !slices.Contains(present, g.Name) {
				add = append(add, g.ID)
				changed = append(changed, g.Name)
			}
		}
		upd.AddTagIDs(add...)
	case tagRemove:
		var remove []int
		for _, g := range tags {
			if slices.Contains(present, g.Name) {
				remove = append(remove, g.ID)
				changed = append(changed, g.Name)
			}
		}
		upd.RemoveTagIDs(remove...)
	}
	if err := upd.Exec(ctx); err != nil {
		return nil, err
	}

	slices.Sort(changed)
	s.Audit(ctx, a, "target.tags", t.Input, tagDetail(mode, changed))

	t, err = s.liveTarget(ctx, id)
	if err != nil {
		return nil, err
	}
	sum := toSummary(t, time.Now())
	return &sum, nil
}

// tagDetail describes a tag write for the audit row.
func tagDetail(mode tagMode, names []string) string {
	switch {
	case mode == tagSet && len(names) == 0:
		return "tags cleared"
	case mode == tagSet:
		return "tags set to " + auditList(names)
	case mode == tagAdd:
		return "tags added " + auditList(names)
	default:
		return "tags removed " + auditList(names)
	}
}

// liveTarget loads a live target with its tags. A missing or soft-deleted
// target is ErrNotFound.
func (s *Service) liveTarget(ctx context.Context, id int) (*ent.Target, error) {
	t, err := s.client.Target.Query().Where(target.ID(id)).WithTags().Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	return t, err
}

// tagsByName resolves tag names to tags. Blank names are skipped. An unknown
// name is an InvalidError listing every one: tags are created by admins in
// the UI, not through the API.
func (s *Service) tagsByName(ctx context.Context, names []string) ([]*ent.Tag, error) {
	var want []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" && !slices.Contains(want, n) {
			want = append(want, n)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	found, err := s.client.Tag.Query().Where(tag.NameIn(want...)).All(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]*ent.Tag, len(found))
	for _, g := range found {
		byName[g.Name] = g
	}
	var out []*ent.Tag
	var unknown []string
	for _, n := range want {
		if g, ok := byName[n]; ok {
			out = append(out, g)
		} else {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		return nil, invalid("tags", "unknown tags: %s (tags are created by an admin in the UI)", strings.Join(unknown, ", "))
	}
	return out, nil
}

func tagIDs(tags []*ent.Tag) []int {
	ids := make([]int, 0, len(tags))
	for _, g := range tags {
		ids = append(ids, g.ID)
	}
	return ids
}

// DeleteTarget soft-deletes a live target. Its history is kept until it is
// purged in the UI.
func (s *Service) DeleteTarget(ctx context.Context, a Actor, id int) error {
	input, err := s.inputOf(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.DeleteTarget(ctx, id); err != nil {
		return notFound(err)
	}
	s.Audit(ctx, a, "target.delete", input, "")
	return nil
}

// RestoreTarget brings a soft-deleted target back with its history.
func (s *Service) RestoreTarget(ctx context.Context, a Actor, id int) error {
	input, err := s.inputOf(ctx, id)
	if err != nil {
		return err
	}
	if err := s.st.RestoreTarget(ctx, id); err != nil {
		return notFound(err)
	}
	s.Audit(ctx, a, "target.restore", input, "")
	return nil
}

// inputOf returns the input of a target, live or soft-deleted, for the audit
// row. A missing target is ErrNotFound.
func (s *Service) inputOf(ctx context.Context, id int) (string, error) {
	t, err := s.client.Target.Get(schema.SkipSoftDelete(ctx), id)
	if ent.IsNotFound(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return t.Input, nil
}

// TargetInput returns the input of a target, live or soft-deleted, so replies
// can say "hostim.dev (#12)" instead of a bare id. A missing target is
// ErrNotFound.
func (s *Service) TargetInput(ctx context.Context, id int) (string, error) {
	return s.inputOf(ctx, id)
}

// notFound maps the storage's missing-target error to ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, storage.ErrTargetNotFound) {
		return ErrNotFound
	}
	return err
}

// RequestRescan queues an on-demand scan of the live targets among ids, with
// the server's cooldown and scan kinds (see SetRescanConfig).
func (s *Service) RequestRescan(ctx context.Context, a Actor, ids []int) (*RescanResult, error) {
	if len(ids) == 0 {
		return nil, invalid("ids", "at least one target is required")
	}
	if len(ids) > maxRescanIDs {
		return nil, invalid("ids", "at most %d targets per call, got %d", maxRescanIDs, len(ids))
	}
	kinds := storage.RescanKinds{SSL: s.sslScanning, CSP: true, Ports: true}
	res, err := s.st.RequestRescan(ctx, ids, time.Now(), s.rescanCooldown, kinds)
	if err != nil {
		return nil, err
	}

	out := &RescanResult{
		Queued:      orEmpty(res.Queued),
		CoolingDown: []RescanCooldown{},
		NotFound:    orEmpty(res.NotFound),
	}
	for _, c := range res.CoolingDown {
		out.CoolingDown = append(out.CoolingDown, RescanCooldown{ID: c.ID, RetryAt: c.RetryAt})
	}

	// Nothing was found, so nothing changed and there is nothing to audit.
	if len(out.Queued) == 0 && len(out.CoolingDown) == 0 {
		return out, nil
	}
	inputs, err := s.inputsOf(ctx, out.Queued)
	if err != nil {
		return nil, err
	}
	object := auditList(inputs)
	if object == "" {
		object = "no targets"
	}
	detail := fmt.Sprintf("%d queued, %d cooling down, %d not found", len(out.Queued), len(out.CoolingDown), len(out.NotFound))
	s.Audit(ctx, a, "target.rescan", object, detail)
	return out, nil
}

// inputsOf returns the inputs of the given live targets, in id order.
func (s *Service) inputsOf(ctx context.Context, ids []int) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.client.Target.Query().
		Where(target.IDIn(ids...)).
		Order(ent.Asc(target.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, t := range rows {
		out = append(out, t.Input)
	}
	return out, nil
}

// orEmpty returns s, or an empty slice for nil, so the JSON shows [] not null.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
