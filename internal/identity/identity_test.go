package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudruntimeguardian/internal/model"
)

func event() model.Event {
	hash := func(parts ...string) string {
		d := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
		return hex.EncodeToString(d[:])
	}
	return model.Event{ID: "test-evt-1", Type: model.EventProcessExec, OccurredAt: time.Now().UTC(), HostID: hash("host", "worker-1"), BootID: "boot-1", Workload: model.Workload{ID: hash("container", "containerd://abc"), Namespace: "finance", Pod: "payment-0", PodUID: "uid-1", ContainerID: "containerd://abc"}, Process: model.Process{EntityID: "process-1", PID: 12, Executable: "/bin/sh"}}
}

type fakeResolver struct {
	pod   Pod
	err   error
	calls int
}

func (f *fakeResolver) LookupPod(_ context.Context, _, _ string) (Pod, error) {
	f.calls++
	return f.pod, f.err
}
func TestVerifyBindsPodNodeAndContainer(t *testing.T) {
	r := &fakeResolver{pod: Pod{UID: "uid-1", Namespace: "finance", Name: "payment-0", Node: "worker-1", ContainerIDs: []string{"containerd://abc"}}}
	v, err := New(r, []NodeCredential{{Node: "worker-1", Token: strings.Repeat("A", 36)}})
	if err != nil {
		t.Fatal(err)
	}
	good := event()
	authenticated := "Bearer " + strings.Repeat("A", 36)
	got, err := v.Verify(context.Background(), authenticated, good)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workload.PodUID != "uid-1" || got.Workload.ID == good.Workload.ID {
		t.Fatalf("unverified workload: %+v", got.Workload)
	}
	got2, err := v.Verify(context.Background(), authenticated, good)
	if err != nil || got2.Workload.ID != got.Workload.ID {
		t.Fatal("idempotent identity", err)
	}
	if r.calls != 2 {
		t.Fatal("must perform live check for each call")
	}
	cases := []struct {
		name   string
		change func(*model.Event)
		pod    func(*Pod)
	}{
		{"spoofed node", func(e *model.Event) { e.HostID = "forged" }, nil},
		{"spoofed container hash", func(e *model.Event) { e.Workload.ID = "forged" }, nil},
		{"spoofed container", func(e *model.Event) { e.Workload.ContainerID = "containerd://other" }, nil},
		{"spoofed pod uid", func(e *model.Event) { e.Workload.PodUID = "uid-other" }, nil},
		{"missing pod uid", func(e *model.Event) { e.Workload.PodUID = "" }, nil},
		{"pod recreated", nil, func(p *Pod) { p.UID = "uid-2" }},
		{"pod moved", nil, func(p *Pod) { p.Node = "worker-2" }},
		{"pod deleting", nil, func(p *Pod) { p.Deleting = true }},
		{"container restarted", nil, func(p *Pod) { p.ContainerIDs = []string{"containerd://new"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := good
			p := r.pod
			if tc.change != nil {
				tc.change(&e)
			}
			if tc.pod != nil {
				tc.pod(&p)
			}
			r.pod = p
			_, err := v.Verify(context.Background(), authenticated, e)
			if !errors.Is(err, ErrMismatch) {
				t.Fatalf("expected mismatch got %v", err)
			}
			r.pod = Pod{UID: "uid-1", Namespace: "finance", Name: "payment-0", Node: "worker-1", ContainerIDs: []string{"containerd://abc"}}
		})
	}
	if _, err := v.Verify(context.Background(), "Bearer wrong", good); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("incorrect auth: %v", err)
	}
	if _, err := v.Verify(context.Background(), "Bearer "+strings.Repeat("B", 36), good); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("wrong token accepted")
	}
	r.err = ErrUnavailable
	if _, err := v.Verify(context.Background(), authenticated, good); !errors.Is(err, ErrUnavailable) {
		t.Fatal("outage must fail closed", err)
	}
	r.err = ErrMismatch
	if _, err := v.Verify(context.Background(), authenticated, good); !errors.Is(err, ErrMismatch) {
		t.Fatal("missing pod must fail closed", err)
	}
}

func TestCredentialFilePermissionsAndUniqueness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	good := []byte(`{"nodes":[{"node":"worker-1","token":"abcdefghijklmnopqrstuvwxyzABCDEF"}]}`)
	if err := os.WriteFile(path, good, 0600); err != nil {
		t.Fatal(err)
	}
	if cred, err := LoadCredentials(path); err != nil || len(cred) != 1 {
		t.Fatalf("valid credentials: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("accepted world-readable secret")
	}
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err != nil {
		t.Fatal("kubernetes group-read secret", err)
	}
	target := filepath.Join(dir, "..2026_10_20_11_00")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "credentials.json"), good, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..2026_10_20_11_00/credentials.json", path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err != nil {
		t.Fatalf("valid projected-secret symlink rejected: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCredentials(path); err == nil {
		t.Fatal("accepted symlink")
	}
	cases := [][]NodeCredential{
		{{Node: "worker-1", Token: strings.Repeat("x", 32)}, {Node: "worker-1", Token: strings.Repeat("y", 32)}},
		{{Node: "worker-1", Token: strings.Repeat("x", 32)}, {Node: "worker-2", Token: strings.Repeat("x", 32)}},
		{{Node: "worker-1", Token: "short"}},
	}
	for _, c := range cases {
		if _, err := New(&fakeResolver{}, c); err == nil {
			t.Fatal("invalid credential config accepted")
		}
	}
}

func TestLiveKubernetesAPIAndTLS(t *testing.T) {
	status := 200
	var apiRequestCount int
	pod := map[string]any{"metadata": map[string]any{"uid": "uid-1", "name": "payment-0", "namespace": "finance"}, "spec": map[string]any{"nodeName": "worker-1"}, "status": map[string]any{"containerStatuses": []any{map[string]string{"containerID": "containerd://abc"}}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequestCount++
		if r.URL.Path != "/api/v1/namespaces/finance/pods/payment-0" || r.Header.Get("Authorization") != "Bearer kube-auth-secret" {
			t.Errorf("unsafe request: %v", r)
		}
		w.WriteHeader(status)
		if status == 200 {
			_ = json.NewEncoder(w).Encode(pod)
		}
	}))
	defer server.Close()
	cert := server.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	client, err := NewKubernetesClient(server.URL, "kube-auth-secret", certPEM)
	if err != nil {
		t.Fatal(err)
	}
	p, err := client.LookupPod(context.Background(), "finance", "payment-0")
	if err != nil || p.UID != "uid-1" || len(p.ContainerIDs) != 1 {
		t.Fatalf("lookup: %+v %v", p, err)
	}
	if apiRequestCount != 1 {
		t.Fatal("no cache expected")
	}
	status = 404
	if _, err := client.LookupPod(context.Background(), "finance", "payment-0"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("404: %v", err)
	}
	status = 503
	if _, err := client.LookupPod(context.Background(), "finance", "payment-0"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("503: %v", err)
	}
	if _, err := NewKubernetesClient("http://localhost:6443", "kube-auth-secret", certPEM); err == nil {
		t.Fatal("plaintext kube API accepted")
	}
	if _, err := NewKubernetesClient(server.URL, "kube-auth-secret", []byte("bad CA")); err == nil {
		t.Fatal("bad CA accepted")
	}
}
