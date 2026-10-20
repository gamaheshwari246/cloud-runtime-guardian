package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/identity"
	"cloudruntimeguardian/internal/model"
)

type kubeMock struct {
	pod identity.Pod
	err error
}

func (m *kubeMock) LookupPod(context.Context, string, string) (identity.Pod, error) {
	return m.pod, m.err
}
func stableHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func TestNodeScopedIngestionRejectsSpoofingAndOutages(t *testing.T) {
	en, err := engine.Open(filepath.Join(t.TempDir(), "events.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	mock := &kubeMock{pod: identity.Pod{UID: "pod-uid-1", Namespace: "finance", Name: "payment-0", Node: "worker-1", ContainerIDs: []string{"containerd://abcd"}}}
	nodeToken := strings.Repeat("n", 48)
	v, err := identity.New(mock, []identity.NodeCredential{{Node: "worker-1", Token: nodeToken}})
	if err != nil {
		t.Fatal(err)
	}
	h := (&API{Engine: en, AdminToken: strings.Repeat("a", 48), Identity: v}).Handler()
	e := model.Event{ID: "source-event-01", Type: model.EventProcessExec, OccurredAt: time.Now().UTC(), HostID: stableHash("host", "worker-1"), BootID: "boot-1", Workload: model.Workload{ID: stableHash("container", "containerd://abcd"), Namespace: "finance", Pod: "payment-0", PodUID: "pod-uid-1", ContainerID: "containerd://abcd"}, Process: model.Process{EntityID: "exec-1", PID: 24, Executable: "/bin/bash"}}
	check := func(label string, event model.Event, token string, want int) {
		t.Helper()
		w := request(t, h, "POST", "/v1/events", encode(t, event), token)
		if w.Code != want {
			t.Fatalf("%s status %d want %d: %s", label, w.Code, want, w.Body.String())
		}
	}
	check("missing token", e, "", 401)
	check("admin token cannot ingest", e, strings.Repeat("a", 48), 401)
	check("wrong node", e, strings.Repeat("x", 48), 401)
	if s := en.Stats(); s.Events != 0 {
		t.Fatal("invalid events were stored")
	}
	check("accepted", e, nodeToken, 202)
	check("duplicate", e, nodeToken, 200)
	if s := en.Stats(); s.Events != 1 {
		t.Fatalf("deduplication failed: %+v", s)
	}
	e.ID = "source-event-02"
	e.HostID = "untrusted-host"
	check("forged host", e, nodeToken, 409)
	e.HostID = stableHash("host", "worker-1")
	mock.pod.UID = "new-pod-uid"
	check("recreated pod", e, nodeToken, 409)
	mock.pod.UID = "pod-uid-1"
	mock.err = identity.ErrUnavailable
	w := request(t, h, "POST", "/v1/events", encode(t, e), nodeToken)
	if w.Code != 503 || w.Header().Get("Retry-After") != "2" {
		t.Fatalf("outage should retry: %d %+v", w.Code, w.Header())
	}
	if s := en.Stats(); s.Events != 1 {
		t.Fatalf("unverified event stored: %+v", s)
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, nodeToken); w.Code != 401 {
		t.Fatalf("source token reads incidents: %d", w.Code)
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, strings.Repeat("a", 48)); w.Code != 200 {
		t.Fatalf("admin token cannot read: %d", w.Code)
	}
}
