package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudruntimeguardian/internal/engine"
	"cloudruntimeguardian/internal/httpapi"
)

const testExec = `{"process_exec":{"process":{"exec_id":"proc-A","pid":321,"binary":"/bin/bash","pod":{"namespace":"test","name":"app","container":{"id":"containerd://a"}}}},"node_name":"worker-1","time":"2026-10-20T01:00:00Z"}`
const testConnect = `{"process_connect":{"process":{"exec_id":"proc-A","pid":321,"binary":"/bin/bash","pod":{"namespace":"test","name":"app","container":{"id":"containerd://a"}}},"destination_ip":"8.8.8.8","destination_port":443,"protocol":"TCP"},"node_name":"worker-1","time":"2026-10-20T01:00:30Z"}`

func setup(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "export.jsonl")
	cfg := Config{ExportPath: src, CheckpointPath: filepath.Join(dir, "checkpoint.json"), NodeName: "worker-1", BootID: "boot-1"}
	return cfg, src
}
func write(t *testing.T, path, raw string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReplayAndDurableCheckpointEndToEnd(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, `{"process_exit":{}}`+"\n"+testConnect+"\n"+testExec+"\n")
	en, err := engine.Open(filepath.Join(t.TempDir(), "journal.jsonl"), 500)
	if err != nil {
		t.Fatal(err)
	}
	defer en.Close()
	srv := httptest.NewServer((&httpapi.API{Engine: en, Token: ""}).Handler())
	defer srv.Close()
	send := HTTPSender{URL: srv.URL + "/v1/events", Client: srv.Client()}
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if stats := en.Stats(); stats.Events != 2 || stats.Incidents != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	cp, ok, err := load(cfg.CheckpointPath)
	if err != nil || !ok || cp.Offset != int64(len(`{"process_exit":{}}`+"\n"+testConnect+"\n"+testExec+"\n")) {
		t.Fatalf("checkpoint: %+v %v", cp, err)
	}
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if stats := en.Stats(); stats.Events != 2 {
		t.Fatalf("replayed events: %+v", stats)
	}
	// Crash between HTTP acknowledgment and checkpoint fsync: replay exact
	// event ID; HTTP 200 must be treated as successful at-least-once replay.
	cp.Offset = int64(len(`{"process_exit":{}}` + "\n"))
	if err := save(cfg.CheckpointPath, cp); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if stats := en.Stats(); stats.Events != 2 || stats.Incidents != 1 {
		t.Fatalf("not idempotent: %+v", stats)
	}
}

func TestFailClosedOnCorruptionAndIdentityChange(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, testExec+"\n")
	sender := SenderFunc(func(_ context.Context, _ []byte) error { return nil })
	if err := Run(context.Background(), cfg, sender); err != nil {
		t.Fatal(err)
	}
	t.Run("truncated", func(t *testing.T) {
		write(t, path, "")
		if err := Run(context.Background(), cfg, sender); err == nil {
			t.Fatal("expected truncated error")
		}
	})
	write(t, path, testExec+"\n")
	t.Run("different boot", func(t *testing.T) {
		other := cfg
		other.BootID = "boot-2"
		if err := Run(context.Background(), other, sender); err == nil {
			t.Fatal("expected boot mismatch")
		}
	})
	t.Run("rotated", func(t *testing.T) {
		if err := os.Rename(path, path+".old"); err != nil {
			t.Fatal(err)
		}
		write(t, path, testExec+"\n")
		if err := Run(context.Background(), cfg, sender); err != nil {
			t.Fatalf("rename/create rotation should recover when old inode retained: %v", err)
		}
	})
}

type SenderFunc func(context.Context, []byte) error

func (f SenderFunc) Send(ctx context.Context, b []byte) error { return f(ctx, b) }

func TestPartialLineAndTooLarge(t *testing.T) {
	cfg, path := setup(t)
	var mu sync.Mutex
	calls := 0
	send := SenderFunc(func(_ context.Context, _ []byte) error { mu.Lock(); defer mu.Unlock(); calls++; return nil })
	write(t, path, testExec)
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("sent an incomplete line")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("\n")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), cfg, send); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("failed to commit completed line")
	}
	cfg2, path2 := setup(t)
	write(t, path2, strings.Repeat("x", maxLine+1)+"\n")
	if err := Run(context.Background(), cfg2, send); err == nil {
		t.Fatal("oversized line accepted")
	}
}

func TestOnSendFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	cfg, path := setup(t)
	write(t, path, testExec+"\n")
	bad := SenderFunc(func(context.Context, []byte) error { return errors.New("disk full") })
	if err := Run(context.Background(), cfg, bad); err == nil {
		t.Fatal("ignored failed send")
	}
	_, exists, err := load(cfg.CheckpointPath)
	if err != nil || exists {
		t.Fatalf("checkpoint advanced: %v %v", exists, err)
	}
	if err := Run(context.Background(), cfg, SenderFunc(func(_ context.Context, b []byte) error { var e map[string]any; return json.Unmarshal(b, &e) })); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSenderNonRetryableRejection(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { n++; w.WriteHeader(http.StatusConflict) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := (HTTPSender{URL: srv.URL}).Send(ctx, []byte(`{}`)); err == nil || n != 1 {
		t.Fatalf("expected immediate error: %v attempts=%d", err, n)
	}
}
