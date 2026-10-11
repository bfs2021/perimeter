package importer

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestRegistryListIsSorted(t *testing.T) {
	r := NewRegistry()
	for _, name := range []string{"namecheap", "gandi", "hetzner_cloud", "hetzner_robot", "manual", "dns_bruteforce"} {
		r.Register(name, func(_ json.RawMessage) (Source, error) { return nil, nil })
	}
	got := r.List()
	if !slices.IsSorted(got) {
		t.Errorf("List() = %v, want sorted", got)
	}
	want := []string{"dns_bruteforce", "gandi", "hetzner_cloud", "hetzner_robot", "manual", "namecheap"}
	if !slices.Equal(got, want) {
		t.Errorf("List() = %v, want %v", got, want)
	}
}
