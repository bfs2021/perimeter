package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuditEvent is one write made through the UI, the REST API or MCP. It keeps
// the actor's email as a snapshot and has no edge to the user, so the history
// survives the user's deletion.
type AuditEvent struct {
	ent.Schema
}

func (AuditEvent) Fields() []ent.Field {
	return []ent.Field{
		field.Time("at").Default(time.Now).Immutable(),
		field.String("actor_email"),
		field.Int("actor_id").Optional().Nillable(),
		field.Enum("source").Values("ui", "api", "mcp"),
		field.String("token_prefix").Optional(),
		field.String("action").NotEmpty(),
		field.String("object"),
		field.String("detail").Optional(),
	}
}

func (AuditEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("at"),
	}
}
