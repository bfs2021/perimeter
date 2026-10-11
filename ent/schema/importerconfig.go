package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

type ImporterConfig struct {
	ent.Schema
}

func (ImporterConfig) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("provider").Values("manual", "dns_bruteforce", "hetzner_cloud", "hetzner_robot", "namecheap", "gandi"),
		field.Bytes("credentials"),
		field.Int64("sync_interval_seconds").Default(3600),
		field.Time("last_sync_at").Optional().Nillable(),
		// Last attempt, successful or not; the sync loop backs off from it.
		field.Time("last_attempt_at").Optional().Nillable(),
		// Error of the last attempt; cleared on a success.
		field.String("last_error").Optional(),
		// Consecutive failed attempts; the sync loop doubles its interval per failure.
		field.Int("consecutive_failures").Default(0),
		field.Bool("enabled").Default(true),
	}
}

func (ImporterConfig) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
