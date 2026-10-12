package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type RecoveryCode struct {
	ent.Schema
}

func (RecoveryCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("code_hash").NotEmpty(),
		field.Time("used_at").Optional().Nillable(),
	}
}

func (RecoveryCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("recovery_codes").
			Unique().
			Required(),
	}
}

func (RecoveryCode) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
