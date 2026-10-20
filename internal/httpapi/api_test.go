package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/model"
)

func testAPI(t *testing.T, token string) http.Handler {
	t.Helper()
	en, err := engine.Open(filepath.Join(t.TempDir(), "journal.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { en.Close() })
	return (&API{Engine: en, Token: token}).Handler()
}
func request(t *testing.T, h http.Handler, method, url string, body []byte, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, url, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
func apiEvents() (model.Event, model.Event) {
	e := model.Event{ID: "shell-1", Type: model.EventProcessExec, OccurredAt: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC), HostID: "host", BootID: "boot", Workload: model.Workload{ID: "workload"}, Process: model.Process{EntityID: "pid-unique", PID: 100, Executable: "/bin/sh"}}
	c := e
	c.ID = "conn-1"
	c.Type = model.EventNetworkConnect
	c.OccurredAt = e.OccurredAt.Add(time.Second)
	c.Network = &model.Network{DestinationIP: "1.1.1.1", DestinationPort: 443, Protocol: "tcp"}
	return e, c
}
func encode(t *testing.T, x any) []byte {
	t.Helper()
	b, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAuthenticationAndHealth(t *testing.T) {
	h := testAPI(t, "secret-token-of-at-least-24-chars")
	if w := request(t, h, "GET", "/healthz", nil, ""); w.Code != 200 {
		t.Fatalf("health %d", w.Code)
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, ""); w.Code != 401 {
		t.Fatalf("unauthenticated=%d", w.Code)
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, "secret-token-of-at-least-24-chars"); w.Code != 200 {
		t.Fatalf("authenticated=%d", w.Code)
	}
}
func TestAPIEndToEndDryRunAndIdempotency(t *testing.T) {
	h := testAPI(t, "")
	sh, conn := apiEvents()
	for _, e := range []model.Event{conn, sh} {
		w := request(t, h, "POST", "/v1/events", encode(t, e), "")
		if w.Code != 202 {
			t.Fatalf("post %s=%d: %s", e.ID, w.Code, w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/v1/events", encode(t, sh), ""); w.Code != 200 {
		t.Fatalf("duplicate=%d", w.Code)
	}
	altered := sh
	altered.Process.Executable = "/bin/bash"
	if w := request(t, h, "POST", "/v1/events", encode(t, altered), ""); w.Code != 409 {
		t.Fatalf("conflict=%d", w.Code)
	}
	got := request(t, h, "GET", "/v1/incidents", nil, "")
	var result struct {
		Total     int              `json:"total"`
		Incidents []model.Incident `json:"incidents"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("want one incident, got %s", got.Body.String())
	}
	id := result.Incidents[0].ID
	act := []byte(`{"request_id":"res-1","action":"block_workload_egress","reason":"Manual analyst approval required"}`)
	target := "/v1/incidents/" + id + "/response"
	r := request(t, h, "POST", target, act, "")
	if r.Code != 201 || !strings.Contains(r.Body.String(), `"enforcement_applied":false`) {
		t.Fatalf("unsafe response: %d %s", r.Code, r.Body.String())
	}
	if r := request(t, h, "POST", target, act, ""); r.Code != 200 {
		t.Fatalf("response retry=%d", r.Code)
	}
	if r := request(t, h, "GET", "/v1/incidents/"+id, nil, ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"responses"`) {
		t.Fatalf("incident get=%d %s", r.Code, r.Body.String())
	}
	if r := request(t, h, "GET", "/v1/stats", nil, ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"dry_run_responses":1`) {
		t.Fatalf("stats=%d %s", r.Code, r.Body.String())
	}
}
func TestStrictJSONAndBodySize(t *testing.T) {
	h := testAPI(t, "")
	sh, _ := apiEvents()
	good := encode(t, sh)
	for name, body := range map[string][]byte{
		"unknown-field":   append(bytes.TrimSuffix(good, []byte("}")), []byte(`,"mystery":true}`)...),
		"multiple-values": append(append([]byte(nil), good...), good...),
		"oversized":       []byte(fmt.Sprintf(`{"id":"%s"}`, strings.Repeat("x", 35<<10))),
	} {
		t.Run(name, func(t *testing.T) {
			w := request(t, h, "POST", "/v1/events", body, "")
			expected := 400
			if name == "oversized" {
				expected = 413
			}
			if w.Code != expected {
				t.Fatalf("expected %d got %d: %s", expected, w.Code, w.Body.String())
			}
		})
	}
	if w := request(t, h, "GET", "/v1/incidents?limit=99999", nil, ""); w.Code != 400 {
		t.Fatalf("invalid pagination=%d", w.Code)
	}
}
func TestResponseCannotSetMode(t *testing.T) {
	h := testAPI(t, "")
	sh, conn := apiEvents()
	request(t, h, "POST", "/v1/events", encode(t, sh), "")
	request(t, h, "POST", "/v1/events", encode(t, conn), "")
	out := request(t, h, "GET", "/v1/incidents", nil, "")
	var listed struct {
		Incidents []model.Incident `json:"incidents"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"request_id":"r-1","action":"block_workload_egress","reason":"example","mode":"enforce"}`)
	w := request(t, h, "POST", "/v1/incidents/"+listed.Incidents[0].ID+"/response", bad, "")
	if w.Code != 400 {
		t.Fatalf("accepted enforcement request: %d", w.Code)
	}
}

func TestSeparatedCredentialsAndNoAnonymousFallback(t *testing.T) {
	en, err := engine.Open(filepath.Join(t.TempDir(), "j"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	h := (&API{Engine: en, IngestToken: "ingest-secret-00000000000000", AdminToken: "admin-secret-000000000000000"}).Handler()
	e, _ := apiEvents()
	if w := request(t, h, "POST", "/v1/events", encode(t, e), "admin-secret-000000000000000"); w.Code != 401 {
		t.Fatalf("admin credential wrote events: %d", w.Code)
	}
	if w := request(t, h, "POST", "/v1/events", encode(t, e), "ingest-secret-00000000000000"); w.Code != 202 {
		t.Fatalf("ingest rejected: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, "ingest-secret-00000000000000"); w.Code != 401 {
		t.Fatalf("collector read incidents: %d", w.Code)
	}
	if w := request(t, h, "GET", "/v1/incidents", nil, "admin-secret-000000000000000"); w.Code != 200 {
		t.Fatalf("admin rejected: %d", w.Code)
	}
	if w := request(t, h, "GET", "/readyz", nil, ""); w.Code != 200 {
		t.Fatalf("probe rejected: %d", w.Code)
	}
	h = (&API{Engine: en, IngestToken: "ingest-secret-00000000000000"}).Handler()
	if w := request(t, h, "GET", "/v1/stats", nil, ""); w.Code != 401 {
		t.Fatalf("missing admin role became anonymous: %d", w.Code)
	}
}

func TestCursorPaginationHTTP(t *testing.T) {
	h := testAPI(t, "")
	shell, conn := apiEvents()
	for i := 0; i < 4; i++ {
		sh := shell
		co := conn
		sh.ID = fmt.Sprintf("sh-%d", i)
		co.ID = fmt.Sprintf("co-%d", i)
		sh.Process.EntityID = fmt.Sprintf("proc-%d", i)
		co.Process.EntityID = sh.Process.EntityID
		sh.OccurredAt = sh.OccurredAt.Add(time.Duration(i) * time.Minute)
		co.OccurredAt = sh.OccurredAt.Add(time.Second)
		for _, e := range []model.Event{sh, co} {
			if w := request(t, h, "POST", "/v1/events", encode(t, e), ""); w.Code != 202 {
				t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
			}
		}
	}
	type page struct {
		Incidents []model.Incident `json:"incidents"`
		Next      string           `json:"next_cursor"`
		Total     int              `json:"total"`
	}
	w := request(t, h, "GET", "/v1/incidents?limit=2&cursor=", nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first page
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Incidents) != 2 || first.Next == "" || first.Total != 4 {
		t.Fatal(w.Body.String())
	}
	w = request(t, h, "GET", "/v1/incidents?limit=2&cursor="+first.Next, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var second page
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Incidents) != 2 || second.Next != "" || second.Incidents[0].ID == first.Incidents[0].ID {
		t.Fatal(w.Body.String())
	}
	for _, path := range []string{"/v1/incidents?limit=2&cursor=invalid!", "/v1/incidents?offset=0&cursor=", "/v1/incidents?cursor=" + strings.Repeat("a", 600)} {
		if w := request(t, h, "GET", path, nil, ""); w.Code != 400 {
			t.Fatalf("accepted bad cursor %s: %d", path, w.Code)
		}
	}
}

func TestContainmentRequiresAdminAndExplicitOperatorMode(t *testing.T) {
	en, err := engine.Open(filepath.Join(t.TempDir(), "ledger.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	sh, conn := apiEvents()
	sh.Workload = model.Workload{ID: "verified-workload", Namespace: "prod", Pod: "payments", PodUID: "pod-uid", ContainerID: "containerd://xyz"}
	conn.Workload = sh.Workload
	for _, e := range []model.Event{sh, conn} {
		if _, err := en.Ingest(e); err != nil {
			t.Fatal(err)
		}
	}
	incidents, _ := en.List(1, 0)
	id := incidents[0].ID
	admin := "an-administrator-credential-12345678"
	ingest := "a-collector-credential-12345678"
	disabled := (&API{Engine: en, AdminToken: admin, IngestToken: ingest}).Handler()
	endpoint := "/v1/incidents/" + id + "/containment"
	body := []byte(`{"request_id":"req-100","ttl_seconds":60,"reason":"Operator approved manual test","confirm_pod_wide":true}`)
	if w := request(t, disabled, "POST", endpoint, body, admin); w.Code != 403 {
		t.Fatalf("disabled endpoint %d", w.Code)
	}
	enabled := (&API{Engine: en, AdminToken: admin, IngestToken: ingest, ContainmentMode: "simulate"}).Handler()
	if w := request(t, enabled, "POST", endpoint, body, ingest); w.Code != 401 {
		t.Fatalf("collector used admin endpoint: %d", w.Code)
	}
	if w := request(t, enabled, "POST", endpoint, []byte(`{"request_id":"req-100","ttl_seconds":60,"reason":"Operator approved manual test"}`), admin); w.Code != 400 {
		t.Fatalf("missing consent %d", w.Code)
	}
	if w := request(t, enabled, "POST", endpoint, body, admin); w.Code != 202 || !strings.Contains(w.Body.String(), `"state":"requested"`) {
		t.Fatalf("containment request %d %s", w.Code, w.Body.String())
	}
	if w := request(t, enabled, "POST", endpoint, body, admin); w.Code != 200 {
		t.Fatalf("idempotent retry %d", w.Code)
	}
	if w := request(t, enabled, "GET", "/v1/containments/req-100", nil, ingest); w.Code != 401 {
		t.Fatalf("collector read incident response %d", w.Code)
	}
	if w := request(t, enabled, "DELETE", "/v1/containments/req-100", nil, admin); w.Code != 202 {
		t.Fatalf("manual release %d %s", w.Code, w.Body.String())
	}
}
