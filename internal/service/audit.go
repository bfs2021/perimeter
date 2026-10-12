package service

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"perimeter/ent"
	"perimeter/ent/auditevent"
	"perimeter/internal/storage"
)

// Sources of a write, stored as the audit source.
const (
	SourceUI  = "ui"
	SourceAPI = "api"
	SourceMCP = "mcp"
)

// maxAuditObject keeps a list of names in one audit row short.
const maxAuditObject = 200

// Actor is who made a write and how: the signed-in user, the transport
// (SourceUI, SourceAPI or SourceMCP) and, for API and MCP calls, the token.
type Actor struct {
	User   *ent.User
	Source string
	Token  *ent.APIToken
}

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID          int       `json:"id"`
	At          time.Time `json:"at"`
	ActorEmail  string    `json:"actor_email"`
	ActorID     *int      `json:"actor_id,omitempty"`
	Source      string    `json:"source"`
	TokenPrefix string    `json:"token_prefix,omitempty"`
	Action      string    `json:"action"`
	Object      string    `json:"object"`
	Detail      string    `json:"detail,omitempty"`
}

// Audit records one write. Insert errors are logged and dropped: a failed
// audit row must never fail the action it describes.
func (s *Service) Audit(ctx context.Context, a Actor, action, object, detail string) {
	create := s.client.AuditEvent.Create().
		SetSource(auditevent.Source(a.Source)).
		SetAction(action).
		SetObject(object).
		SetDetail(detail)
	// The email is a snapshot, so the row still names the user after the user
	// is deleted. It is required, so a write with no user records an empty one.
	email := ""
	if a.User != nil {
		email = a.User.Email
		create.SetActorID(a.User.ID)
	}
	create.SetActorEmail(email)
	if a.Token != nil {
		create.SetTokenPrefix(a.Token.Prefix)
	}
	if _, err := create.Save(ctx); err != nil {
		log.Printf("audit %s: %v", action, err)
	}
}

// ListAudit returns one page of the audit log, newest first.
func (s *Service) ListAudit(ctx context.Context, limit, offset int) (Page[AuditEntry], error) {
	if offset < 0 {
		return Page[AuditEntry]{}, invalid("offset", "must not be negative")
	}
	limit = clampLimit(limit, defaultLimit, maxLimit)
	q := s.client.AuditEvent.Query()
	total, err := q.Clone().Count(ctx)
	if err != nil {
		return Page[AuditEntry]{}, err
	}
	rows, err := q.
		Order(ent.Desc(auditevent.FieldAt), ent.Desc(auditevent.FieldID)).
		Limit(limit).
		Offset(offset).
		All(ctx)
	if err != nil {
		return Page[AuditEntry]{}, err
	}
	items := make([]AuditEntry, 0, len(rows))
	for _, r := range rows {
		items = append(items, AuditEntry{
			ID:          r.ID,
			At:          r.At,
			ActorEmail:  r.ActorEmail,
			ActorID:     r.ActorID,
			Source:      string(r.Source),
			TokenPrefix: r.TokenPrefix,
			Action:      r.Action,
			Object:      r.Object,
			Detail:      r.Detail,
		})
	}
	return newPage(items, total, offset), nil
}

// ImportAudit is the object and detail of a "target.import" audit row for an
// import result. The UI import uses it too, so both paths log the same text.
func ImportAudit(res storage.ImportResult) (object, detail string) {
	touched := slices.Concat(res.Added, res.Restored, res.Existing)
	object = auditList(touched)
	if object == "" {
		object = auditList(res.Invalid)
	}
	detail = fmt.Sprintf("%d added, %d restored, %d invalid", len(res.Added), len(res.Restored), len(res.Invalid))
	return object, detail
}

// auditList joins names for an audit object and cuts it to maxAuditObject
// bytes, on a rune boundary, with an ellipsis when it was cut.
func auditList(names []string) string {
	joined := strings.Join(names, ", ")
	if len(joined) <= maxAuditObject {
		return joined
	}
	cut := maxAuditObject
	for !utf8.RuneStart(joined[cut]) {
		cut--
	}
	return joined[:cut] + "…"
}
