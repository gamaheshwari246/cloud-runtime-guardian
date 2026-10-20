package containment

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudruntimeguardian/internal/identity"
	"cloudruntimeguardian/internal/model"
)

type fakeCluster struct {
	mu            sync.Mutex
	uid           string
	label         string
	policy        map[string]any
	badPolicy     bool
	mutationCount int
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(r.URL.Path, "/pods/payments") {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"uid": f.uid, "name": "payments", "namespace": "prod", "labels": map[string]string{labelKey: f.label}}, "spec": map[string]any{"nodeName": "worker-1"}, "status": map[string]any{"containerStatuses": []map[string]string{{"containerID": "containerd://123"}}}})
		case http.MethodPatch:
			var ops []map[string]any
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				w.WriteHeader(400)
				return
			}
			if len(ops) < 2 || ops[0]["op"] != "test" || ops[0]["value"] != f.uid {
				w.WriteHeader(409)
				return
			}
			if len(ops) == 2 && ops[1]["op"] == "add" {
				f.label = ops[1]["value"].(string)
			} else if len(ops) == 3 && ops[2]["op"] == "remove" && f.label == ops[1]["value"] {
				f.label = ""
			} else {
				w.WriteHeader(422)
				return
			}
			f.mutationCount++
			_, _ = w.Write([]byte(`{"status":"Success"}`))
		default:
			w.WriteHeader(405)
		}
		return
	}
	if strings.Contains(r.URL.Path, "/networkpolicies") {
		if r.Method == http.MethodGet && r.URL.Path == "/apis/networking.k8s.io/v1/networkpolicies" {
			items := []any{}
			if f.policy != nil {
				items = append(items, f.policy)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"continue": ""}, "items": items})
			return
		}
		switch r.Method {
		case http.MethodPost:
			if f.policy != nil {
				w.WriteHeader(409)
				return
			}
			if err := json.NewDecoder(r.Body).Decode(&f.policy); err != nil {
				w.WriteHeader(400)
				return
			}
			meta := f.policy["metadata"].(map[string]any)
			meta["uid"] = "netpol-immutable-uid"
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
			return
		case http.MethodGet:
			if f.policy == nil {
				w.WriteHeader(404)
				return
			}
			if f.badPolicy {
				_, _ = w.Write([]byte(`{"metadata":{"annotations":{"security.cloudruntimeguardian.dev/containment-id":"impostor"}}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.policy)
			return
		case http.MethodDelete:
			if f.policy == nil {
				w.WriteHeader(404)
				return
			}
			f.policy = nil
			f.mutationCount++
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
			return
		}
	}
	w.WriteHeader(404)
}
func setupCluster(t *testing.T) (*KubernetesBackend, *fakeCluster, model.Containment) {
	t.Helper()
	f := &fakeCluster{uid: "original-uid"}
	server := httptest.NewTLSServer(f)
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	pods, err := identity.NewKubernetesClient(server.URL, "test-token-123", ca)
	if err != nil {
		t.Fatal(err)
	}
	b := &KubernetesBackend{BaseURL: server.URL, Client: server.Client(), Pods: pods, Token: func() (string, error) { return "test-token-123", nil }}
	now := time.Now().UTC()
	c := model.Containment{ID: "request-1", IncidentID: "incident-1", Workload: model.Workload{ID: "verified", Namespace: "prod", Pod: "payments", PodUID: f.uid, ContainerID: "containerd://123"}, State: "requested", Mode: "kubernetes", Reason: "Verified test isolation", RequestedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Minute)}
	return b, f, c
}
func TestKubernetesBackendCreateRepairAndRelease(t *testing.T) {
	b, f, c := setupCluster(t)
	if err := b.Ensure(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := b.Ensure(context.Background(), c); err != nil {
		t.Fatal("idempotent reconcile failed:", err)
	}
	f.mu.Lock()
	active := f.policy != nil && f.label == labelValue(c)
	f.mu.Unlock()
	if !active {
		t.Fatal("policy and pod selector not configured")
	}
	if err := b.Release(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := b.Release(context.Background(), c); err != nil {
		t.Fatal("release is not idempotent:", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil || f.label != "" {
		t.Fatal("pod isolation not removed")
	}
}
func TestKubernetesBackendRefusesPodReplacement(t *testing.T) {
	b, f, c := setupCluster(t)
	f.mu.Lock()
	f.uid = "replacement-uid"
	f.mu.Unlock()
	if err := b.Ensure(context.Background(), c); err == nil {
		t.Fatal("accepted replaced pod")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil || f.label != "" || f.mutationCount != 0 {
		t.Fatal("mutated replacement pod")
	}
}
func TestKubernetesBackendRefusesExistingForeignPolicy(t *testing.T) {
	b, f, c := setupCluster(t)
	f.mu.Lock()
	f.policy = map[string]any{"foreign": true}
	f.badPolicy = true
	f.mu.Unlock()
	if err := b.Ensure(context.Background(), c); err == nil {
		t.Fatal("accepted foreign policy")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.label != "" {
		t.Fatal("labeled pod despite policy conflict")
	}
}
func TestKubernetesBackendRejectsExpiredRequest(t *testing.T) {
	b, f, c := setupCluster(t)
	old := time.Now().Add(-2 * time.Minute)
	c.RequestedAt = old
	c.UpdatedAt = old
	c.ExpiresAt = old.Add(time.Minute)
	if err := b.Ensure(context.Background(), c); err == nil {
		t.Fatal("accepted expired containment")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil {
		t.Fatal("installed expired policy")
	}
}

func TestExpiredPolicySweeperIsIndependent(t *testing.T) {
	b, f, c := setupCluster(t)
	if err := b.Ensure(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	removed, err := b.SweepExpired(context.Background(), c.ExpiresAt.Add(-time.Second))
	if err != nil || removed != 0 {
		t.Fatalf("premature release %d %v", removed, err)
	}
	removed, err = b.SweepExpired(context.Background(), c.ExpiresAt.Add(time.Second))
	if err != nil || removed != 1 {
		t.Fatalf("expired policy not removed %d %v", removed, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy != nil {
		t.Fatal("expired policy still installed")
	}
}
func TestExpiredPolicySweeperRejectsForeignPolicy(t *testing.T) {
	b, f, c := setupCluster(t)
	if err := b.Ensure(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	meta := f.policy["metadata"].(map[string]any)
	meta["name"] = "foreign-policy"
	f.mu.Unlock()
	removed, err := b.SweepExpired(context.Background(), c.ExpiresAt.Add(time.Second))
	if err != nil || removed != 0 {
		t.Fatalf("deleted unrelated policy %d %v", removed, err)
	}
}
