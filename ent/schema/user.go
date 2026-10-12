package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type User struct {
	ent.Schema
}

func (User) Fields() []ent.Field {
	return []ent.Field{
		field.String("email").Unique().NotEmpty(),
		field.String("name").Default(""),
		field.String("password_hash").Optional().Nillable(),
		field.Bool("confirmed").Default(false),
		field.Enum("role").Values("admin", "member", "viewer").Default("member"),
		field.Time("last_login_at").Optional().Nillable(),
		field.String("totp_secret").Optional().Sensitive(),
		field.Bool("totp_enabled").Default(false),
		field.Int64("totp_last_step").Default(0),
		field.Int("totp_failures").Default(0),
		field.Time("totp_locked_until").Optional().Nillable(),
	}
}

func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("targets", Target.Type),
		edge.To("sessions", Session.Type),
		edge.To("invites", Invite.Type),
		edge.To("recovery_codes", RecoveryCode.Type),
		edge.To("login_challenges", LoginChallenge.Type),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
