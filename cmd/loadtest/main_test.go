package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHistogramBounded(t *testing.T) {
	var h histogram
	for _, d := range []time.Duration{0, time.Millisecond, 3 * time.Millisecond, 20 * time.Second} {
		h.observe(d)
	}
	if got := h.percentile(1, 4); got != 10000*time.Millisecond {
		t.Fatal(got)
	}
	if got := h.percentile(.5, 4); got != time.Millisecond {
		t.Fatal(got)
	}
}
func TestLoadGenerator(t *testing.T) {
	var received atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" || r.Method != "POST" {
			t.Error("wrong request")
		}
		received.Add(1)
		w.WriteHeader(202)
	}))
	defer server.Close()
	out, err := run(context.Background(), server.Client(), server.URL+"/v1/events", "", "test", 4, 40, 200*time.Millisecond, 0, time.Second)
	if err != nil || !out.Passed || out.Succeeded < 2 || out.Failed > 0 || out.Succeeded != received.Load() {
		t.Fatalf("%+v %v", out, err)
	}
}
func TestDisallowInsecureRemote(t *testing.T) {
	_, err := run(context.Background(), &http.Client{}, "http://example.com/v1/events", "", "test", 1, 1, time.Second, 0, time.Second)
	if err == nil {
		t.Fatal("remote HTTP accepted")
	}
}
