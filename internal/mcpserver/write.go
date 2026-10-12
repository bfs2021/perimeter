package mcpserver

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"perimeter/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxRescanTargets caps one rescan call. It is well under the service's own
// cap, so one model turn cannot queue a large batch.
const maxRescanTargets = 50

// addWriteTools registers the write tools. They are listed only for callers
// that CanWrite, and each write is audited with the MCP source.
func (t *toolset) addWriteTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "add_targets",
		Description: "Start tracking targets: hostnames, IP addresses or URLs (reduced to the host), one per entry. Adding is additive and safe to repeat: targets already tracked are left as they are, and soft-deleted ones are restored with their history. New targets are scanned on the next cycles.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.addTargets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "set_tags",
		Description: "Change the tags of one target. mode replace sets its tags to exactly the list given, add adds them, and remove takes them off. Tags must already exist; admins create them in the UI. Repeating a call gives the same result. target is an id or a name.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, t.setTags)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_target",
		Description: "Soft-delete a target: it leaves the lists and is no longer scanned, but its history is kept, and restore_target brings it back. target is an id or a name.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, t.deleteTarget)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "restore_target",
		Description: "Bring back a soft-deleted target with its history. target is an id or a name.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, t.restoreTarget)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "rescan",
		Description: "Queue an on-demand scan of up to 50 targets, given as names or ids. Each target has a cooldown between rescans; one still cooling down is not queued and its retry_at time is returned. Scans run in the background, so results appear later: check get_target or changes_since afterwards.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(true)},
	}, t.rescan)
}

// maxListedTargets caps the target lines a write reply lists.
const maxListedTargets = 25

type addTargetsIn struct {
	Inputs []string `json:"inputs" jsonschema:"Targets to track: hostnames, IP addresses or URLs, one per entry. A URL is reduced to its host. Up to 1000 entries per call."`
}

func (t *toolset) addTargets(ctx context.Context, _ *mcp.CallToolRequest, in addTargetsIn) (*mcp.CallToolResult, service.ImportResult, error) {
	if len(in.Inputs) == 0 {
		return nil, service.ImportResult{}, badArg("inputs", "at least one target is required")
	}
	res, err := t.svc.ImportTargets(ctx, t.actor, in.Inputs)
	if err != nil {
		return nil, service.ImportResult{}, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "added %d, restored %d, already tracked %d, invalid %d",
		len(res.Added), len(res.Restored), len(res.Existing), len(res.Invalid))
	if len(res.Invalid) > 0 {
		b.WriteString("\ninvalid: " + strings.Join(res.Invalid, ", "))
	}
	for i, ref := range res.Targets {
		if i == maxListedTargets {
			fmt.Fprintf(&b, "\n%d more", len(res.Targets)-maxListedTargets)
			break
		}
		fmt.Fprintf(&b, "\n#%d %s (%s)", ref.ID, ref.Input, ref.Status)
	}
	return reply(b.String(), *res)
}

type setTagsIn struct {
	Target string   `json:"target" jsonschema:"The target: a numeric id such as 12, or the name of the target such as example.com."`
	Tags   []string `json:"tags" jsonschema:"Tag names. With mode replace an empty list removes every tag."`
	Mode   string   `json:"mode" jsonschema:"replace sets the tags to exactly this list. add adds them to the current tags. remove takes them off the target."`
}

func (t *toolset) setTags(ctx context.Context, _ *mcp.CallToolRequest, in setTagsIn) (*mcp.CallToolResult, service.TargetSummary, error) {
	var write func(context.Context, service.Actor, int, []string) (*service.TargetSummary, error)
	switch in.Mode {
	case "replace":
		write = t.svc.SetTargetTags
	case "add":
		write = t.svc.AddTargetTags
	case "remove":
		write = t.svc.RemoveTargetTags
	default:
		return nil, service.TargetSummary{}, badArg("mode", "must be replace, add or remove, not %q", in.Mode)
	}
	id, err := t.targetID(ctx, in.Target)
	if err != nil {
		return nil, service.TargetSummary{}, err
	}
	sum, err := write(ctx, t.actor, id, in.Tags)
	if err != nil {
		return nil, service.TargetSummary{}, notFound(in.Target, "live target", err)
	}
	return reply("updated "+targetLine(*sum), *sum)
}

// ActionOut is the reply of delete_target and restore_target.
type ActionOut struct {
	ID     int    `json:"id"`
	Status string `json:"status"`
}

type targetWriteIn struct {
	Target string `json:"target" jsonschema:"The target: a numeric id such as 12, or the name of the target such as example.com."`
}

func (t *toolset) deleteTarget(ctx context.Context, _ *mcp.CallToolRequest, in targetWriteIn) (*mcp.CallToolResult, ActionOut, error) {
	id, err := t.targetID(ctx, in.Target)
	if err != nil {
		return nil, ActionOut{}, err
	}
	if err := t.svc.DeleteTarget(ctx, t.actor, id); err != nil {
		return nil, ActionOut{}, notFound(in.Target, "live target", err)
	}
	return reply(fmt.Sprintf("deleted #%d; restore_target brings it back with its history", id),
		ActionOut{ID: id, Status: "deleted"})
}

func (t *toolset) restoreTarget(ctx context.Context, _ *mcp.CallToolRequest, in targetWriteIn) (*mcp.CallToolResult, ActionOut, error) {
	id, err := t.targetID(ctx, in.Target)
	if err != nil {
		return nil, ActionOut{}, err
	}
	if err := t.svc.RestoreTarget(ctx, t.actor, id); err != nil {
		return nil, ActionOut{}, notFound(in.Target, "soft-deleted target", err)
	}
	return reply(fmt.Sprintf("restored #%d with its history", id), ActionOut{ID: id, Status: "restored"})
}

type rescanIn struct {
	Targets []string `json:"targets" jsonschema:"Targets to scan: ids such as 12 or names such as example.com. At most 50 per call."`
}

func (t *toolset) rescan(ctx context.Context, _ *mcp.CallToolRequest, in rescanIn) (*mcp.CallToolResult, service.RescanResult, error) {
	if len(in.Targets) == 0 {
		return nil, service.RescanResult{}, badArg("targets", "at least one target is required")
	}
	if len(in.Targets) > maxRescanTargets {
		return nil, service.RescanResult{}, badArg("targets", "at most %d targets per call, got %d", maxRescanTargets, len(in.Targets))
	}
	// Every target must resolve before anything is queued, so a typo does
	// not leave the call half done.
	var ids []int
	for _, arg := range in.Targets {
		id, err := t.targetID(ctx, arg)
		if err != nil {
			return nil, service.RescanResult{}, err
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	res, err := t.svc.RequestRescan(ctx, t.actor, ids)
	if err != nil {
		return nil, service.RescanResult{}, err
	}

	var b strings.Builder
	if len(res.Queued) > 0 {
		b.WriteString("queued: " + joinIDs(res.Queued) + "\n")
	}
	for _, c := range res.CoolingDown {
		fmt.Fprintf(&b, "cooling down: #%d, retry at %s\n", c.ID, formatTime(c.RetryAt))
	}
	if len(res.NotFound) > 0 {
		b.WriteString("not found: " + joinIDs(res.NotFound) + "\n")
	}
	b.WriteString("Scans run in the background; check get_target or changes_since later.")
	return reply(b.String(), *res)
}
