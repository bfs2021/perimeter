package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// APIToken is a bearer token for the REST API and MCP. Only its SHA-256 hash
// is stored; prefix is the start of the raw token, kept so it can be shown.
type APIToken struct {
	ent.Schema
}

func (APIToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").NotEmpty().MaxLen(100),
		field.Enum("scope").Values("read", "write"),
		field.String("token_hash").Unique().NotEmpty().Sensitive(),
		field.String("prefix").NotEmpty(),
		field.Time("expires_at").Optional().Nillable(),
		field.Time("last_used_at").Optional().Nillable(),
		field.Time("revoked_at").Optional().Nillable(),
	}
}

func (APIToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("api_tokens").
			Unique().
			Required(),
	}
}

func (APIToken) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
