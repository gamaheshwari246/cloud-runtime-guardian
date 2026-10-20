package incidentindex

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestOrderedPaginationAndDedup(t *testing.T) {
	for _, seed := range []int64{1, 42, 99} {
		rng := rand.New(rand.NewSource(seed))
		idx := &Index{}
		var expected []Key
		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for n := 0; n < 3000; n++ {
			k := Key{At: base.Add(time.Duration(rng.Intn(1200)) * time.Second), ID: fmt.Sprintf("id-%04d", n)}
			if !idx.Insert(k) || idx.Insert(k) {
				t.Fatalf("dedup: %v", k)
			}
			expected = append(expected, k)
		}
		sort.Slice(expected, func(a, b int) bool { return less(expected[a], expected[b]) })
		if idx.Len() != len(expected) {
			t.Fatal("length mismatch")
		}
		for start := 0; start < len(expected); start += 31 {
			got := idx.Page(start, 31)
			for j, k := range got {
				if k != expected[start+j] {
					t.Fatalf("rank %d: got %+v want %+v", start+j, k, expected[start+j])
				}
			}
			if len(got) != min(31, len(expected)-start) {
				t.Fatal("short page")
			}
			if start > 0 {
				gotAfter := idx.PageAfter(expected[start-1], 31)
				if len(got) != len(gotAfter) {
					t.Fatal("cursor short page")
				}
				for j, k := range got {
					if k != gotAfter[j] {
						t.Fatalf("cursor %d: %+v != %+v", j, k, gotAfter[j])
					}
				}
			}
		}
		// A new incident inserted before a cursor must not shift the next page.
		last := expected[100]
		idx.Insert(Key{At: base.Add(10 * time.Hour), ID: "newer"})
		if got := idx.PageAfter(last, 1); len(got) != 1 || got[0] != expected[101] {
			t.Fatalf("unstable cursor: %+v", got)
		}
	}
}

func TestEmptyAndBoundary(t *testing.T) {
	idx := &Index{}
	if len(idx.Page(0, 10)) != 0 || len(idx.PageAfter(Key{}, 10)) != 0 {
		t.Fatal("empty index")
	}
	base := time.Unix(0, 0)
	idx.Insert(Key{At: base, ID: "a"})
	if len(idx.Page(-1, 10)) != 0 || len(idx.Page(0, 0)) != 0 || len(idx.Page(1, 10)) != 0 {
		t.Fatal("invalid offsets")
	}
	if got := idx.PageAfter(Key{At: base, ID: "a"}, 10); len(got) != 0 {
		t.Fatal(got)
	}
}
