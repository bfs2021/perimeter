package scanner

import (
	"testing"

	"perimeter/ent"
)

// A target picked for an SSL rescan yields a job that asks for a fresh
// assessment; an ordinary target does not.
func TestSSLJobFreshFollowsRescanFlag(t *testing.T) {
	pending := sslJob(&ent.Target{Input: "example.com", SslRescanPending: true})
	if !pending.Fresh || pending.Input != "example.com" || pending.Type != JobTypeSSLScan {
		t.Errorf("pending job = %+v, want a fresh SSL job for example.com", pending)
	}
	if sslJob(&ent.Target{Input: "example.com"}).Fresh {
		t.Errorf("ordinary SSL job is marked fresh")
	}
}
