package httpapi

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"cloudruntimeguardian/internal/engine"
)

func TestOperationalEndpointsAndAuth(t *testing.T) {
	en, err := engine.Open(filepath.Join(t.TempDir(), "journal.jsonl"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	h := (&API{Engine: en, Token: strings.Repeat("x", 32)}).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, path, nil))
		if r.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, r.Code)
		}
	}
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if r.Code != http.StatusUnauthorized {
		t.Fatalf("metrics not protected: %d", r.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	r = httptest.NewRecorder()
	h.ServeHTTP(r, req)
	if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "crg_ready 1") || !strings.Contains(r.Body.String(), "crg_events_stored 0") {
		t.Fatalf("bad metrics %d: %s", r.Code, r.Body.String())
	}
}
