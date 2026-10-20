package identity

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCredentialRotationIsAtomicAndRejectsBadUpdate(t *testing.T) {
	old := strings.Repeat("o", 36)
	next := strings.Repeat("n", 36)
	v, err := New(&fakeResolver{}, []NodeCredential{{Node: "node-1", Token: old}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.authenticate("Bearer " + old); err != nil {
		t.Fatal(err)
	}
	if err := v.ReplaceCredentials([]NodeCredential{{Node: "node-2", Token: "short"}}); err == nil {
		t.Fatal("invalid rotation accepted")
	}
	if _, err := v.authenticate("Bearer " + old); err != nil {
		t.Fatal("failed rotation disabled existing token")
	}
	if err := v.ReplaceCredentials([]NodeCredential{{Node: "node-2", Token: next}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.authenticate("Bearer " + old); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old token accepted: %v", err)
	}
	if node, err := v.authenticate("Bearer " + next); err != nil || node != "node-2" {
		t.Fatalf("new token: %s %v", node, err)
	}
}

func TestConcurrentCredentialRotationAndAuthentication(t *testing.T) {
	old, next := strings.Repeat("a", 36), strings.Repeat("b", 36)
	v, err := New(&fakeResolver{}, []NodeCredential{{Node: "n1", Token: old}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_, err := v.authenticate("Bearer " + old)
				if err != nil && !errors.Is(err, ErrUnauthenticated) {
					t.Errorf("unexpected auth error: %v", err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			if err := v.ReplaceCredentials([]NodeCredential{{Node: "n1", Token: next}}); err != nil {
				t.Error(err)
			}
			if err := v.ReplaceCredentials([]NodeCredential{{Node: "n1", Token: old}}); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
}
