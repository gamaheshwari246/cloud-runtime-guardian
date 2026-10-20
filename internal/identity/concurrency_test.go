package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockedResolver struct {
	started chan struct{}
	release chan struct{}
	pod     Pod
}

func (r *blockedResolver) LookupPod(ctx context.Context, _, _ string) (Pod, error) {
	select {
	case r.started <- struct{}{}:
	case <-ctx.Done():
		return Pod{}, ctx.Err()
	}
	select {
	case <-r.release:
		return r.pod, nil
	case <-ctx.Done():
		return Pod{}, ctx.Err()
	}
}
func TestLiveIdentityLookupHasBoundedConcurrency(t *testing.T) {
	r := &blockedResolver{started: make(chan struct{}, 17), release: make(chan struct{}), pod: Pod{UID: "uid-1", Namespace: "finance", Name: "payment-0", Node: "worker-1", ContainerIDs: []string{"containerd://abc"}}}
	v, err := New(r, []NodeCredential{{Node: "worker-1", Token: strings.Repeat("K", 36)}})
	if err != nil {
		t.Fatal(err)
	}
	auth := "Bearer " + strings.Repeat("K", 36)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(context.Background(), auth, event()); err != nil {
				t.Error(err)
			}
		}()
	}
	for i := 0; i < 16; i++ {
		select {
		case <-r.started:
		case <-time.After(3 * time.Second):
			close(r.release)
			wg.Wait()
			t.Fatal("lookup did not start")
		}
	}
	if _, err := v.Verify(context.Background(), auth, event()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("overload not rejected with retryable error: %v", err)
	}
	close(r.release)
	wg.Wait()
	if _, err := v.Verify(context.Background(), auth, event()); err != nil {
		t.Fatalf("no recovery after capacity freed: %v", err)
	}
}
