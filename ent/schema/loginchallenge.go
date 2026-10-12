package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type LoginChallenge struct {
	ent.Schema
}

func (LoginChallenge) Fields() []ent.Field {
	return []ent.Field{
		field.String("token_hash").Unique().NotEmpty(),
		field.Time("expires_at"),
		field.Int("attempts").Default(0),
	}
}

func (LoginChallenge) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("login_challenges").
			Unique().
			Required(),
	}
}

func (LoginChallenge) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
