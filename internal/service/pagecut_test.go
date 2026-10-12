package service

import (
	"testing"
	"time"
)

func TestPageCutKeepsEqualTimesTogether(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	at := func(secs ...int) []Change {
		out := make([]Change, len(secs))
		for i, s := range secs {
			out[i] = Change{At: t0.Add(time.Duration(s) * time.Second)}
		}
		return out
	}
	for _, tc := range []struct {
		name  string
		all   []Change
		limit int
		want  int
	}{
		{"distinct times", at(1, 2, 3, 4), 2, 2},
		{"group across the boundary", at(1, 2, 2, 3), 2, 1},
		{"group fills the page", at(2, 2, 2, 3), 2, 3},
	} {
		if got := pageCut(tc.all, tc.limit); got != tc.want {
			t.Errorf("%s: cut = %d, want %d", tc.name, got, tc.want)
		}
	}
}
